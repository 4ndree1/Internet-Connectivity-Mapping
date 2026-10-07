"""
GroupEngine — a manually-assigned cluster of devices from ONE monitored
network, with its own independent dashboard.

HOW IT FITS TOGETHER
--------------------
A NetHealerEngine owns everything network-facing for one /24: ARP
discovery, the per-device ping/TCP/speed probes, name resolution. A group
does NOT run a second set of probes against the same devices — that would
double the ping/TCP load on them and bring back the exact lag the engine's
bounded worker pool was built to prevent. Instead a GroupEngine presents
the parent's live NetworkDevice objects (only the members) to the UI
through thin per-group views, and owns everything that should be
independent per group:

  * its own device list / summary counts / filters / IP search (the UI
    builds a normal dashboard panel for it, exactly like a network),
  * continuous monitoring — a group has no pause; its devices are always
    probed by the parent's health loop, exactly like a normal network,
  * its own History Log clear point (clearing it never touches the
    network's or another group's history),
  * its own bandwidth totals (per device and group-wide), persisted under
    a "group:<id>" key in bandwidth_store, with their own daily reset,
  * its own Troubleshoot Log,
  * its own network-wide-spike detection over just its members.

The UI reads an engine through a small duck-typed surface (devices, lock,
label, gateway_ip, get_bandwidth_snapshot, clear_history, ...). This class
implements that same surface, which is what lets the existing
_build_dashboard / refresh_panel / radar / history / troubleshoot code be
reused for groups without a second copy of any of it.

LOCKING
-------
self.lock IS the parent's lock (a plain, non-reentrant threading.Lock), so
group readers stay consistent with the parent's health writers. The UI
often does `with engine.lock: ... engine.devices ...`, so the `devices`
property below must never take that lock itself (it would self-deadlock).
"""

import atexit
import random
import threading
import time
from datetime import datetime

import bandwidth_store
import group_store
from engine import NetHealerEngine

_TICK_SEC = 2.0
_MAX_LOG_LINES = 300


def _norm(mac):
    return group_store.normalize_mac(mac)


def unwrap_device(device):
    """Returns the real NetworkDevice behind a group view (or the object
    itself if it's already a real device)."""
    return getattr(device, "_dev", device)


class _GroupDeviceView:
    """Read-through wrapper around one real NetworkDevice, as seen from
    one group. Everything (name, ip, status, latency, ...) is the live
    value from the real device; only the values that must differ per
    group are overridden: the status history (filtered by this group's
    clear point) and the bandwidth estimate (this group's own counter).
    Writes pass straight through to the real device."""

    def __init__(self, group, dev):
        object.__setattr__(self, "_group", group)
        object.__setattr__(self, "_dev", dev)

    def __getattr__(self, name):
        # Only reached for names NOT found on the view itself.
        return getattr(object.__getattribute__(self, "_dev"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_dev"), name, value)

    @property
    def status_history(self):
        dev = object.__getattribute__(self, "_dev")
        group = object.__getattribute__(self, "_group")
        hist = getattr(dev, "status_history", None) or []
        cutoff = group.history_cleared_at
        if not cutoff:
            return list(hist)
        # Entry timestamps are "%Y-%m-%d %H:%M:%S", so plain string
        # comparison orders them correctly.
        return [e for e in hist if str(e.get("ts", "")) >= cutoff]

    @property
    def _bw_estimated_bytes(self):
        dev = object.__getattribute__(self, "_dev")
        group = object.__getattribute__(self, "_group")
        return group._dev_totals.get(_norm(dev.mac), 0.0)


class GroupEngine:
    is_group = True

    # Same formatter the network engine uses.
    _format_bytes = staticmethod(NetHealerEngine._format_bytes)

    def __init__(self, ui, parent, record):
        self.ui = ui
        self.parent = parent
        self.group_id = record["id"]
        self.name = record.get("name") or "GROUP"
        self._members = {_norm(m) for m in record.get("macs", []) if m}
        self.history_cleared_at = record.get("history_cleared_at") or None
        self.created = record.get("created")

        self.lock = parent.lock          # shared on purpose — see module docstring
        self.running = True
        self.paused = False  # groups are never paused; kept for engine-loop compatibility
        self.auto_troubleshoot_logs = []
        self._panel_ref = None

        self.network_wide_issue = False
        self.network_wide_since = None
        self._on_streak = 0
        self._off_streak = 0

        self._views = {}                 # normalized mac -> _GroupDeviceView

        # Independent bandwidth accounting (see _accumulate_bandwidth).
        self._bw_key = f"group:{self.group_id}"
        self._dev_totals = {}
        self._last_seen = {}
        self._network_total = bandwidth_store.load_network_estimated_total(self._bw_key)
        self._bw_last_reset_date = None
        for mac in self._members:
            self._dev_totals[mac] = bandwidth_store.load_for_mac(self._bw_key, mac)

        atexit.register(self._flush_on_exit)
        threading.Thread(target=self._loop, daemon=True).start()

    # ---- identity ------------------------------------------------------
    @property
    def label(self):
        tag = self.parent.label.split("-")[0].strip() or self.parent.label
        return f"GROUP: {self.name}   -   {tag}"

    @property
    def gateway_ip(self):
        return self.parent.gateway_ip

    @property
    def gateways(self):
        return self.parent.gateways

    @property
    def base_ip(self):
        return self.parent.base_ip

    @property
    def network_key(self):
        return self.parent.network_key

    # ---- membership ----------------------------------------------------
    def members(self):
        return set(self._members)

    def set_members(self, macs):
        new_members = {_norm(m) for m in macs if m}
        for mac in new_members - self._members:
            self._dev_totals.setdefault(
                mac, bandwidth_store.load_for_mac(self._bw_key, mac))
        self._members = new_members
        for mac in list(self._views):
            if mac not in new_members:
                self._views.pop(mac, None)
        self.parent._rebuild_group_maps()

    def to_record(self):
        return {
            "id": self.group_id,
            "name": self.name,
            "macs": sorted(self._members),
            "created": self.created,
            "history_cleared_at": self.history_cleared_at,
        }

    def _persist(self):
        group_store.save_group(self.parent.network_key, self.to_record())

    def rename(self, new_name):
        self.name = new_name
        self._persist()

    @property
    def devices(self):
        """Live views of the member devices currently present on the
        parent network, in the parent's order. Deliberately lock-free —
        see the LOCKING note in the module docstring."""
        members = self._members
        out = []
        for dev in list(self.parent.devices):
            mac = _norm(dev.mac)
            if mac not in members:
                continue
            view = self._views.get(mac)
            if view is None or view._dev is not dev:
                view = _GroupDeviceView(self, dev)
                self._views[mac] = view
            out.append(view)
        return out

    # ---- troubleshoot log (own, independent) ---------------------------
    def add_troubleshoot_log(self, msg):
        return  # legacy no-op, same as NetHealerEngine

    def add_auto_troubleshoot_log(self, msg):
        with self.lock:
            self.auto_troubleshoot_logs.append(f"> {msg}")
            trimmed = len(self.auto_troubleshoot_logs) > _MAX_LOG_LINES
            if trimmed:
                self.auto_troubleshoot_logs.pop(0)
        if trimmed:
            self.ui.after(0, lambda: self.ui.refresh_auto_troubleshoot_log(self))
        else:
            self.ui.after(0, lambda m=msg: self.ui.append_auto_troubleshoot_log_line(self, m))

    # ---- history (own clear point) -------------------------------------
    def clear_history(self):
        """Hides everything logged so far from THIS group's History Log.
        The network's own history and other groups' are untouched (the
        underlying device entries stay; this group just stops showing
        anything older than now)."""
        self.history_cleared_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._persist()

    # ---- bandwidth (own totals) ----------------------------------------
    def _accumulate_bandwidth(self):
        """Adds each member's growth since the last tick to this group's
        own counters. Reading deltas off the parent's per-device estimate
        (instead of recomputing anything) means no extra probing; a drop
        in the parent's figure (its own clear / midnight reset) is treated
        as a fresh start for that device, not as negative usage."""
        by_mac = {_norm(d.mac): d for d in list(self.parent.devices)}
        for mac in self._members:
            dev = by_mac.get(mac)
            if dev is None:
                continue
            cur = float(getattr(dev, "_bw_estimated_bytes", 0.0) or 0.0)
            last = self._last_seen.get(mac)
            if last is not None:
                delta = cur - last if cur >= last else cur
                if delta > 0:
                    self._dev_totals[mac] = self._dev_totals.get(mac, 0.0) + delta
                    self._network_total += delta
            self._last_seen[mac] = cur

    def _push_bandwidth(self):
        bandwidth_store.save_totals(self._bw_key, dict(self._dev_totals))
        bandwidth_store.save_network_estimated_total(self._bw_key, self._network_total)

    def _reset_bandwidth_at_midnight_if_needed(self):
        today = datetime.now().date().isoformat()
        if self._bw_last_reset_date == today:
            return
        try:
            if not bandwidth_store.daily_reset_needed(self._bw_key, today):
                self._bw_last_reset_date = today
                return
            bandwidth_store.clear_network(self._bw_key)
            bandwidth_store.mark_daily_reset(self._bw_key, today)
            for mac in list(self._dev_totals):
                self._dev_totals[mac] = 0.0
            self._network_total = 0.0
            self._bw_last_reset_date = today
        except Exception:
            pass

    def clear_device_bandwidth(self, mac):
        mac = _norm(mac)
        if not mac:
            return
        self._dev_totals[mac] = 0.0
        bandwidth_store.clear_device(self._bw_key, mac)

    def clear_bandwidth_totals(self):
        for mac in list(self._dev_totals):
            self._dev_totals[mac] = 0.0
        self._network_total = 0.0
        bandwidth_store.clear_network(self._bw_key)

    def get_bandwidth_snapshot(self):
        """Same shape as NetHealerEngine.get_bandwidth_snapshot, but the
        estimated figures are THIS group's own counters. The REAL
        (OS-interface) numbers are a whole-host figure that can't be
        split per group, so they're reported as unavailable here."""
        snap = self.parent.get_bandwidth_snapshot()
        rows = []
        for view in self.devices:
            est = self._dev_totals.get(_norm(view.mac), 0.0)
            rows.append((view.name, view.ip, view.mac, view.status, est))
        rows.sort(key=lambda r: r[4], reverse=True)
        total = sum(r[4] for r in rows)
        snap.update({
            "network_total_available": False,
            "bytes_sent": 0, "bytes_recv": 0, "bytes_total": 0,
            "formatted_total": "--", "formatted_sent": "--", "formatted_recv": "--",
            "estimated_total_bytes": total,
            "formatted_estimated_total": self._format_bytes(total) if rows else "--",
            "network_estimated_bytes": self._network_total,
            "formatted_network_estimated_total": self._format_bytes(self._network_total),
            "devices": [
                {"name": n, "ip": ip, "mac": mac, "status": st,
                 "estimated_bytes": est, "formatted_estimate": self._format_bytes(est)}
                for n, ip, mac, st, est in rows
            ],
        })
        return snap

    def get_device_bandwidth_history(self, mac):
        return self.parent.get_device_bandwidth_history(mac)

    def _flush_on_exit(self):
        try:
            self._push_bandwidth()
            bandwidth_store.flush_now()
        except Exception:
            pass

    # ---- diagnostics (delegated; probing belongs to the parent) --------
    def run_diagnostic(self, device, on_complete, on_progress=None):
        return self.parent.run_diagnostic(unwrap_device(device), on_complete, on_progress)

    def get_diagnostic_snapshot(self, device):
        return self.parent.get_diagnostic_snapshot(unwrap_device(device))

    def _analyze_possible_causes(self, device, results):
        return self.parent._analyze_possible_causes(unwrap_device(device), results)

    # ---- lifecycle -----------------------------------------------------
    def stop(self):
        self.running = False
        self._flush_on_exit()

    def _loop(self):
        time.sleep(random.uniform(0.2, 1.0))
        while self.running:
            try:
                self._tick()
            except Exception:
                pass  # one bad tick must never kill this group's heartbeat
            time.sleep(_TICK_SEC)

    def _tick(self):
        self._reset_bandwidth_at_midnight_if_needed()
        self._accumulate_bandwidth()
        self._evaluate_spike()
        self._push_bandwidth()

    def _evaluate_spike(self):
        """Same rule as the network engine (>= 3 devices, >= 60% degraded,
        debounced over 2 cycles) but over this group's members only."""
        devs = self.devices
        total = len(devs)
        degraded = sum(1 for d in devs if d.status in ("Unstable", "Offline"))
        meets = total >= 3 and (degraded / total) >= 0.6
        if meets:
            self._on_streak += 1
            self._off_streak = 0
        else:
            self._off_streak += 1
            self._on_streak = 0
        was = self.network_wide_issue
        if not was and self._on_streak >= 2:
            self.network_wide_issue = True
            self.network_wide_since = datetime.now().strftime("%H:%M:%S")
        elif was and self._off_streak >= 2:
            self.network_wide_issue = False
            self.network_wide_since = None
        if was != self.network_wide_issue:
            self.ui.after(0, lambda: self.ui.request_panel_refresh(self))