"""
Persistent storage for each device's cumulative ESTIMATED bandwidth
consumption (engine.py's device._bw_estimated_bytes).

Same rationale and same on-disk location as history_store.py: this lives
in the OS's per-user "app data" folder, outside wherever the app itself
is installed/unpacked, so a device's running total survives closing the
app, or even deleting/reinstalling it — but not a manual wipe of that
app-data folder.

Scoped the same way as history_store: network first, then MAC, so two
different monitored networks never mix totals, and clearing one doesn't
touch another. A device that stops showing up on the dashboard (its
network was removed, or it simply isn't part of the current scan) is
naturally left out of anything computed from the live device list —
this store only answers "what was this MAC's saved total", it never
sums across every MAC it has ever seen.

WHY AN IN-MEMORY CACHE + BACKGROUND WRITER (unlike history_store):
history_store.append_entry() only runs on real, infrequent events (a
device's status actually changing), so a full read-modify-write of its
file each time is cheap in practice. Bandwidth totals update every
single ~2s health-loop cycle for every device, on EVERY monitored
network's own background thread — if save_totals() did a real disk
read+write each time it was called, a setup with several monitored
networks would mean several full-file JSON parses and rewrites landing
close together, repeatedly, forever. That was showing up as real,
noticeable lag/stutter once this feature was added, especially with
more than a couple of networks or a larger device count.

Instead, save_totals() only updates an in-memory dict and returns
immediately — no disk access on the hot path at all. A single shared
background thread wakes up periodically and writes that in-memory state
to disk ONLY if something actually changed since the last write. Every
monitored network's engine funnels through this same cache and the same
writer thread, so no matter how many networks are being watched, disk
writes happen at one fixed, gentle cadence rather than once per network.
flush_now() forces an immediate synchronous write for the one moment
that actually needs it: app shutdown (see engine.py's atexit hook),
since a daemon thread can be killed mid-sleep before it gets to run.

File format: {"<network_key>": {"<mac address>": <cumulative_bytes>, ...}, ...}
"""

import json
import os
import threading
import time

import history_store

_FILE_NAME = "bandwidth_log.json"

# Reserved top-level key for the REAL (OS-interface-counter) network-wide
# sent/recv totals carried over across app restarts — see
# load_network_real_total/save_network_real_total below. Kept separate
# from the per-network buckets above (which are keyed by network_key and
# hold {mac: bytes}) so there's no ambiguity between a real MAC address
# and this reserved key. A network_key built from a base_ip/gateway MAC
# never takes this literal form, so no real network can collide with it.
_NETWORK_TOTALS_KEY = "__network_real_totals__"

# Reserved top-level key for the ESTIMATED network-wide total — the
# running sum of every device's own estimated consumption, kept as its
# own monotonic figure (see save_network_estimated_total below for why)
# rather than summed on the fly from the per-device buckets above. Kept
# separate from _NETWORK_TOTALS_KEY (the REAL OS-counter total) and from
# the per-MAC buckets so all three are never confused with each other.
_NETWORK_ESTIMATED_TOTAL_KEY = "__network_estimated_totals__"
# Reserved bucket for the last calendar date on which each network
# bandwidth total was reset automatically at local midnight.
_DAILY_RESET_DATES_KEY = "__daily_reset_dates__"

# How often the background writer checks whether there's anything new to
# save. Independent from (and much simpler than) engine.py's own
# _BW_FLUSH_INTERVAL_SEC — that constant only controls how often each
# engine pushes its devices' latest numbers into this module's in-memory
# cache (cheap); this constant controls how often that cache actually
# touches disk (not cheap), regardless of how many networks are pushing
# updates into it.
_WRITE_INTERVAL_SEC = 5

_lock = threading.Lock()
_cache = None             # lazily loaded from disk, then kept in memory
_dirty = False             # True when _cache has changes not yet on disk
_writer_started = False


def _bandwidth_file():
    # Reuse history_store's persistent-dir resolution (same app-data
    # folder, same fallback-to-home behavior) rather than duplicating it.
    return os.path.join(history_store.get_persistent_dir(), _FILE_NAME)


def _load_cache_locked():
    """Populates the module-level cache from disk on first use. Must be
    called with `_lock` already held."""
    global _cache
    if _cache is not None:
        return _cache
    path = _bandwidth_file()
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            # Corrupt/partial file (e.g. app killed mid-write) — start
            # fresh rather than crashing the app over a broken total.
            data = {}
    _cache = data
    return _cache


def _write_cache_locked():
    """Writes the current in-memory cache to disk. Must be called with
    `_lock` already held."""
    if _cache is None:
        return
    path = _bandwidth_file()
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(_cache, f, indent=2)
        os.replace(tmp_path, path)  # atomic on every OS we target
    except Exception:
        pass


def _writer_loop():
    global _dirty
    while True:
        time.sleep(_WRITE_INTERVAL_SEC)
        with _lock:
            if _dirty:
                _write_cache_locked()
                _dirty = False


def _ensure_writer_thread():
    global _writer_started
    with _lock:
        if _writer_started:
            return
        _writer_started = True
    threading.Thread(target=_writer_loop, daemon=True).start()


def load_for_mac(network_key, mac):
    """Returns the saved cumulative byte total for one device on one
    network (0.0 if none saved yet)."""
    if not mac or not network_key:
        return 0.0
    with _lock:
        data = _load_cache_locked()
        try:
            return float(data.get(network_key, {}).get(mac, 0.0))
        except (TypeError, ValueError):
            return 0.0


def save_totals(network_key, totals_by_mac):
    """Updates the in-memory total for every MAC in `totals_by_mac` (a
    {mac: cumulative_bytes} dict) under this network. Disk-free and fast
    — safe to call once per monitored network every health cycle without
    that network's monitoring loop ever waiting on disk I/O. The actual
    save to disk happens separately and periodically; see the background
    writer thread started by _ensure_writer_thread()."""
    global _dirty
    if not network_key or not totals_by_mac:
        return
    _ensure_writer_thread()
    with _lock:
        data = _load_cache_locked()
        net_bucket = data.setdefault(network_key, {})
        for mac, total in totals_by_mac.items():
            if mac:
                net_bucket[mac] = float(total)
        _dirty = True


def load_network_real_total(network_key):
    """Returns the persisted REAL (OS-interface-counter) sent/recv byte
    totals carried over from earlier sessions for this network, as
    {"sent": float, "recv": float} (zeros if nothing saved yet).

    This is a completely different number from the per-MAC ESTIMATED
    totals above (see engine.get_bandwidth_snapshot's docstring for the
    real-vs-estimated distinction) — kept in its own reserved bucket
    (_NETWORK_TOTALS_KEY) so the two are never confused with each other.
    engine._resolve_bandwidth_interface() calls this once when a new
    monitoring session starts, so the REAL total displayed keeps
    growing across app restarts instead of silently resetting to zero
    every time the interface's OS-level byte counters get a fresh
    baseline for the new session."""
    if not network_key:
        return {"sent": 0.0, "recv": 0.0}
    with _lock:
        data = _load_cache_locked()
        entry = data.get(_NETWORK_TOTALS_KEY, {}).get(network_key, {})
        try:
            return {
                "sent": float(entry.get("sent", 0.0)),
                "recv": float(entry.get("recv", 0.0)),
            }
        except (TypeError, ValueError):
            return {"sent": 0.0, "recv": 0.0}


def save_network_real_total(network_key, sent_bytes, recv_bytes):
    """Updates the in-memory total for this network's REAL sent/recv
    bytes. Disk-free and fast, same treatment as save_totals() above —
    safe to call once per health cycle. The values passed in should
    already be this session's carried-forward total (previous sessions'
    saved total plus this session's own delta so far — see
    engine.get_bandwidth_snapshot), so what's on disk only ever grows,
    the same way the per-device ESTIMATED totals do."""
    global _dirty
    if not network_key:
        return
    _ensure_writer_thread()
    with _lock:
        data = _load_cache_locked()
        bucket = data.setdefault(_NETWORK_TOTALS_KEY, {})
        bucket[network_key] = {"sent": float(sent_bytes), "recv": float(recv_bytes)}
        _dirty = True


def load_network_estimated_total(network_key):
    """Returns the persisted ESTIMATED network-wide total (sum of every
    device's own estimated consumption, accumulated over time) for this
    network — 0.0 if nothing saved yet.

    This is a running figure that only ever grows, distinct from both
    the REAL per-interface total (load_network_real_total) and from
    simply summing the current per-device buckets on the fly: engine.py
    adds to it every time a device's own estimate grows, but clearing
    ONE device's saved total (clear_device) deliberately does NOT
    subtract anything from this figure — see save_network_estimated_total
    below for why."""
    if not network_key:
        return 0.0
    with _lock:
        data = _load_cache_locked()
        try:
            return float(data.get(_NETWORK_ESTIMATED_TOTAL_KEY, {}).get(network_key, 0.0))
        except (TypeError, ValueError):
            return 0.0


def save_network_estimated_total(network_key, total_bytes):
    """Updates the in-memory ESTIMATED network-wide total for this
    network. Disk-free and fast, same treatment as save_totals() above —
    safe to call once per health cycle.

    Deliberately a separate, independently-persisted figure rather than
    something derived by summing the per-device buckets at read time:
    the per-device buckets shrink whenever clear_device() resets one
    device (by design — that's what "clear this device's total" means),
    but the network-wide total should keep counting everything that was
    ever attributed to it, past or present devices alike, so clearing
    one device's own total doesn't make the network total appear to
    shrink. engine.py is responsible for only ever passing in a
    monotonically increasing value here (this session's running total),
    the same discipline save_network_real_total's caller already
    follows for the REAL total."""
    global _dirty
    if not network_key:
        return
    _ensure_writer_thread()
    with _lock:
        data = _load_cache_locked()
        bucket = data.setdefault(_NETWORK_ESTIMATED_TOTAL_KEY, {})
        bucket[network_key] = float(total_bytes)
        _dirty = True


def daily_reset_needed(network_key, date_key):
    """Return True when this network has not yet been reset for date_key."""
    if not network_key or not date_key:
        return False
    with _lock:
        data = _load_cache_locked()
        return data.get(_DAILY_RESET_DATES_KEY, {}).get(network_key) != str(date_key)


def mark_daily_reset(network_key, date_key):
    """Record the calendar date of the most recent automatic midnight reset."""
    global _dirty
    if not network_key or not date_key:
        return
    _ensure_writer_thread()
    with _lock:
        data = _load_cache_locked()
        bucket = data.setdefault(_DAILY_RESET_DATES_KEY, {})
        bucket[network_key] = str(date_key)
        _dirty = True


def clear_network(network_key):
    """Wipes only the saved bandwidth totals for one network — every
    device's saved total AND this network's saved ESTIMATED network-wide
    total — leaving every other monitored network's saved totals
    untouched. Writes to disk immediately — this only runs on an
    explicit user action, not on the frequent per-cycle path, so there's
    no lag concern here."""
    global _dirty
    if not network_key:
        return
    with _lock:
        data = _load_cache_locked()
        changed = False
        if network_key in data:
            del data[network_key]
            changed = True
        est_bucket = data.get(_NETWORK_ESTIMATED_TOTAL_KEY)
        if est_bucket and network_key in est_bucket:
            del est_bucket[network_key]
            changed = True
        if changed:
            _write_cache_locked()
            _dirty = False


def clear_device(network_key, mac):
    """Wipes the saved bandwidth total for one specific device on one
    network, leaving every other device (on this network or any other)
    untouched. Used by the per-device Bandwidth popup's CLEAR button.
    Writes to disk immediately, same reasoning as clear_network."""
    global _dirty
    if not network_key or not mac:
        return
    with _lock:
        data = _load_cache_locked()
        net_bucket = data.get(network_key)
        if net_bucket and mac in net_bucket:
            del net_bucket[mac]
            _write_cache_locked()
            _dirty = False


def clear_all():
    """Wipes the saved bandwidth-totals file entirely — every network,
    every device."""
    global _cache, _dirty
    with _lock:
        _cache = {}
        _dirty = False
        path = _bandwidth_file()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def flush_now():
    """Forces an immediate synchronous write of whatever's currently in
    memory, bypassing the periodic writer thread. Meant for the one
    moment that genuinely needs it: app shutdown (see engine.py's atexit
    hook) — a daemon thread can be killed mid-sleep before it ever gets
    a chance to run, so exit is the one path that can't rely on it."""
    global _dirty
    with _lock:
        if _cache is not None:
            _write_cache_locked()
        _dirty = False