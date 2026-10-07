import threading
import subprocess
import socket
import re
import time
import platform
from datetime import datetime
from models import NetworkDevice, STATUS_COLORS
import statistics
import random
import history_store
import bandwidth_store
import group_store
import atexit
import concurrent.futures
from collections import deque


# Scapy is optional: when it's installed AND the process has permission to
# send raw packets (root/admin, plus Npcap on Windows), it lets us send a
# real ARP request onto the wire and wait for a genuine reply — this is
# ground truth, since it isn't reading anyone's cache (fresh, stale, or
# otherwise). When it's missing or unusable, everything falls back to the
# existing OS-arp-table approach further down this file.
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


# psutil is optional too: when installed, it gives real per-interface byte
# counters straight from the OS, which is what the Bandwidth panel uses for
# this network's actual data total. Without it, that panel just says the
# real total isn't available here instead of guessing at one.
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except Exception:
    _PSUTIL_AVAILABLE = False


# Used only by the per-device bandwidth ESTIMATE (see the comment in
# update_health where this is applied). The packet-pair probe measures
# link CAPACITY (how fast the connection *could* go), not actual usage —
# a device just sitting there idle still answers pings and still has a
# measurable link speed, so integrating that speed as if it were sustained
# the entire time hugely overstates real usage for anything that isn't
# constantly, maximally transferring data. This factor scales that raw
# capacity-based estimate down to a more plausible "typical utilization"
# level for an ordinary device doing ordinary things (occasional
# browsing/streaming/sync, not a constant full-speed transfer). It's still
# a rough assumption, not a measurement — there's no way to know any one
# device's real duty cycle without router-side traffic visibility this
# app doesn't have — but it keeps the numbers in a believable range
# instead of climbing as if every device were maxing out its link
# nonstop. Devices that are genuinely busier still show comparatively
# higher estimates than idle ones, since the underlying speed reading
# still varies; this only rescales the overall magnitude.
_ASSUMED_UTILIZATION_FACTOR = 0.08

# How often (in seconds) each engine pushes its devices' running
# _bw_estimated_bytes totals into bandwidth_store's in-memory cache. That
# push itself is disk-free and fast (see bandwidth_store's module
# docstring), so this interval isn't about avoiding disk I/O directly —
# it's just no reason to re-copy every device's number into the shared
# cache on literally every 2s health cycle when this cadence is already
# far more often than the number meaningfully changes.
_BW_FLUSH_INTERVAL_SEC = 20

# Shared by every NetHealerEngine instance in this process — NOT one pool
# per engine. proactive_scan() (the one-time full-/24 "wake up" sweep run
# when a network starts monitoring) used to spawn up to ~254 ping
# subprocesses AND up to ~254 raw OS threads doing TCP probes, per
# network, with no cap at all. That's tolerable for a single network, but
# the common flow is picking several networks in the network picker and
# hitting start together — each one's proactive_scan() runs on its own
# thread, so their bursts overlap: 3-5 networks meant 750-1250+
# subprocess/thread creations landing within the same couple of seconds,
# which is exactly the kind of spike that made update_health need its own
# bounded worker pool in the first place (see NetHealerEngine.__init__'s
# _health_pool comment) — proactive_scan just never got the same
# treatment. A pool declared here at module level, and reused by every
# engine, is what actually bounds the TOTAL in-flight ping/TCP-probe work
# across every network's startup sweep at once, not just one network's
# own share of it. 40 keeps a single network's sweep fast while still
# leaving real headroom under the process/thread limits that were
# getting hit before.
_PROACTIVE_SCAN_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=40, thread_name_prefix="proactive-scan"
)


def _scapy_arp_resolve(ip, timeout=1.0):
    """
    Send one active ARP request for `ip` and wait up to `timeout` seconds
    for a reply, bypassing the OS's ARP cache entirely.


    Returns a (status, mac) tuple:
      - ("ok", "aa:bb:cc:dd:ee:ff")  probe sent, device answered
      - ("ok", None)                 probe sent cleanly, nobody answered
                                      (this is a real "not there", not an
                                      error — no fallback needed)
      - ("no_permission", None)      scapy can't send raw packets here
                                      (no root/admin, or missing Npcap)
      - ("unavailable", None)        scapy isn't installed
      - ("error", None)              anything else unexpected
    """
    if not _SCAPY_AVAILABLE:
        return "unavailable", None
    try:
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=timeout, verbose=False, retry=0
        )
        if answered:
            return "ok", answered[0][1].hwsrc.lower()
        return "ok", None
    except PermissionError:
        return "no_permission", None
    except Exception as e:
        # Npcap-missing and "socket.error: [Errno 1] Operation not
        # permitted" style failures on Linux/macOS don't always surface
        # as PermissionError — catch by message so we still degrade
        # gracefully instead of crashing the health-check loop.
        msg = str(e).lower()
        if "permitted" in msg or "permission" in msg or "root" in msg or "administrator" in msg or "npcap" in msg:
            return "no_permission", None
        return "error", None


def _scapy_icmp_ping(ip, count=6, timeout=0.3, payload_bytes=0, inter_packet_delay=0.02, warmup=False):
    """
    Send `count` ICMP echo requests ourselves, one at a time, timing each
    round trip with time.perf_counter() — a high-resolution clock available
    on every platform. This replaces trusting the OS ping tool's own
    self-reported "time=Xms" text, which on Windows is rounded to whole
    milliseconds (no decimals at all), and which on every platform is
    still just someone else's timer, not one we control end-to-end.

    `payload_bytes` pads the ICMP packet with that many extra bytes of data.
    Left at 0 for normal latency/jitter/loss sampling (smallest possible
    packet, least likely to be dropped by a router/firewall along the way).
    Callers doing packet-pair bandwidth estimation pass a large value here
    for a second, separate burst — see _estimate_speed_mbps.

    `inter_packet_delay` is a small pause AFTER each reply (skipped on the
    last packet) before sending the next one. Without it, `count` packets
    go out back-to-back as fast as the OS/driver will accept them — on
    WiFi especially, that self-generated burst can itself cause queueing/
    contention on the air, inflating the very RTTs being measured (most
    noticeable as elevated latency+jitter on a device that's physically
    close with a clear signal, where none of that delay should exist).
    Spacing packets out gives the radio time to settle between probes so
    the reading better reflects a normal single ping rather than a
    self-induced traffic spike.

    Returns a (status, latencies_ms) tuple. `status` follows the same
    convention as _scapy_arp_resolve: "ok" means the probe ran (an empty
    latencies list just means every packet was lost, which is a real
    result, not an error); "no_permission" / "unavailable" / "error" mean
    the caller should fall back to the OS ping approach instead.
    """
    if not _SCAPY_AVAILABLE:
        return "unavailable", []
    latencies = []
    try:
        # The first ICMP packet can include ARP/neighbor resolution and
        # therefore is not a clean measurement of the path RTT. Warm up
        # only when the caller is collecting the main latency/jitter/loss
        # sample set; bandwidth packet-pair probes deliberately do not use
        # a warm-up because they need the two probes to remain a true pair.
        if warmup:
            warmup_pkt = IP(dst=ip) / ICMP(seq=0)
            sr1(warmup_pkt, timeout=timeout, verbose=False)
            if inter_packet_delay > 0:
                time.sleep(inter_packet_delay)

        for seq in range(count):
            pkt = IP(dst=ip) / ICMP(seq=seq)
            if payload_bytes > 0:
                from scapy.all import Raw
                pkt = pkt / Raw(b"x" * payload_bytes)
            t0 = time.perf_counter()
            reply = sr1(pkt, timeout=timeout, verbose=False)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if reply is not None:
                latencies.append(elapsed_ms)
            if inter_packet_delay > 0 and seq < count - 1:
                time.sleep(inter_packet_delay)
        return "ok", latencies
    except PermissionError:
        return "no_permission", []
    except Exception as e:
        msg = str(e).lower()
        if "permitted" in msg or "permission" in msg or "root" in msg or "administrator" in msg or "npcap" in msg:
            return "no_permission", []
        return "error", []




def _parse_ping_times(text):
    """
    Extract per-packet RTTs (ms) from OS ping output. Each reply line is
    counted exactly once: "time=Xms" -> X, and Windows' "time<1ms" -> 0.5
    (midpoint of 0-1ms, since the exact value isn't reported). Previously
    "time<1ms" was matched by BOTH the generic time[=<] regex (as 1.0) and
    a separate time<1ms pass (as 0.5), double-counting every sub-millisecond
    reply and skewing the average/jitter.
    """
    times = []
    for op, val in re.findall(r"time\s*([=<])\s*([\d\.]+)", text):
        try:
            v = float(val)
        except ValueError:
            continue
        times.append(v / 2.0 if op == "<" else v)
    return times


_IS_WIN = __import__('platform').system().lower() == "windows"
_NO_WINDOW = __import__('subprocess').CREATE_NO_WINDOW if _IS_WIN else 0


def _run(*args, **kwargs):
    kwargs.setdefault("creationflags", _NO_WINDOW)
    return __import__('subprocess').run(*args, **kwargs)


def _popen(*args, **kwargs):
    kwargs.setdefault("creationflags", _NO_WINDOW)
    return __import__('subprocess').Popen(*args, **kwargs)




# ---------------------------------------------------------------------------
# Multi-size ICMP slope probe (per-device speed estimate)
#
# Why this replaces the old per-pair median:
#   * The old code diffed ONE small and ONE large probe per pair, threw away
#     every pair whose delta was <= 0 or implied > _MAX_PLAUSIBLE_MBPS, then
#     took the median of whatever survived. Dropping the "bad" pairs only on
#     one side biases the survivors toward LARGER deltas, i.e. it
#     systematically UNDER-reads speed (that is why a x2 fudge was needed in
#     the display code).
#   * Queueing/contention noise only ever ADDS delay. The standard fix
#     (used by pathchar/bprobe-style tools) is a MIN filter: for each packet
#     size keep the lowest RTT seen over a rolling window, because the lowest
#     RTT is the one closest to "pure serialization + fixed delay".
#   * With 3 sizes instead of 2, the speed comes from the SLOPE of
#     min-RTT vs. packet size (least squares), so one odd point can't decide
#     the result and the fixed per-device ICMP/processing delay (the
#     intercept) cancels out.
#
# Same ICMP load per device as before (6 sends/cycle).
# ---------------------------------------------------------------------------
_SPEED_PROBE_SIZES = (32, 700, 1400)   # ICMP payload bytes
_SPEED_WINDOW_SAMPLES = 24             # per size, ~12 cycles at 2 probes/cycle/size
_SPEED_MIN_SAMPLES = 4                 # min RTTs needed at the smallest AND largest size


def _speed_mbps_from_size_windows(windows, max_mbps=1200.0):
    """windows: {payload_bytes: iterable of RTTs in ms}. Returns Mbps or None.

    Least-squares slope of (min RTT in window) vs payload size. A round trip
    carries every payload byte twice (request + echo reply), so
    Mbps = 16 bits-per-byte-pair / slope(ms per byte) -> 0.016 / slope.
    """
    pts = []
    sizes = sorted(s for s, w in windows.items() if w)
    if len(sizes) < 2:
        return None
    # need enough samples at the two extremes for the min filter to mean something
    if len(windows[sizes[0]]) < _SPEED_MIN_SAMPLES or len(windows[sizes[-1]]) < _SPEED_MIN_SAMPLES:
        return None
    for s in sizes:
        pts.append((float(s), min(windows[s])))
    n = len(pts)
    mx = sum(p[0] for p in pts) / n
    my = sum(p[1] for p in pts) / n
    sxx = sum((p[0] - mx) ** 2 for p in pts)
    if sxx <= 0:
        return None
    slope = sum((p[0] - mx) * (p[1] - my) for p in pts) / sxx   # ms per byte
    if slope <= 0:
        return None
    mbps = 0.016 / slope
    if mbps > max_mbps:
        return None
    return round(mbps, 1)


def _update_speed_windows(device, size_rtts, max_mbps=1200.0):
    """Feed this cycle's {size: [rtt_ms,...]} into the device's rolling
    windows and return the current slope estimate (or None)."""
    wins = getattr(device, "_speed_rtt_windows", None)
    if wins is None:
        wins = {}
        device._speed_rtt_windows = wins
    for size, rtts in size_rtts.items():
        w = wins.get(size)
        if w is None:
            w = deque(maxlen=_SPEED_WINDOW_SAMPLES)
            wins[size] = w
        w.extend(rtts)
    return _speed_mbps_from_size_windows(wins, max_mbps)


def _scapy_multisize_probe(ip, rounds=2, sizes=_SPEED_PROBE_SIZES, timeout=0.3, gap=0.02):
    """Send `rounds` interleaved sweeps over `sizes` (small, mid, large,
    small, ...) so every size sees about the same link conditions. Returns
    {size: [rtt_ms, ...]}. If the largest size gets no reply twice in a row
    the device/firewall is dropping big ICMP, so stop instead of burning
    the rest of the timeouts."""
    out = {s: [] for s in sizes}
    if not _SCAPY_AVAILABLE:
        return out
    big_misses = 0
    for _ in range(rounds):
        for s in sizes:
            _, rtts = _scapy_icmp_ping(ip, count=1, timeout=timeout,
                                       payload_bytes=s, inter_packet_delay=0.0)
            if rtts:
                out[s].append(rtts[0])
                if s == sizes[-1]:
                    big_misses = 0
            elif s == sizes[-1]:
                big_misses += 1
            if gap > 0:
                time.sleep(gap)
        if big_misses >= 2:
            break
    return out



class NetHealerEngine:
    # Shared across every engine instance in this process — each new
    # monitored network/tab increments this, and the count at the time
    # an engine is created becomes its stagger slot (see _health_loop).
    # Without this, every engine's health loop phase-locks onto the same
    # 2s boundary (they're all created and finish their initial scan at
    # roughly the same time), so on a multi-network setup ALL windows'
    # ping/TCP/bandwidth bursts — and their UI redraws — land in the same
    # instant instead of being spread out, which is its own separate
    # source of lag on top of any single network's own device count.
    _engine_instance_counter = 0

    def __init__(self, ui, base_ip=None, label=None):
        self.ui = ui
        self.devices = []
        NetHealerEngine._engine_instance_counter += 1
        self._stagger_slot = NetHealerEngine._engine_instance_counter
        # One dedicated troubleshoot log per network.
        # This is the ONLY troubleshoot log used by the dashboard.
        self.auto_troubleshoot_logs = []
        self.lock = threading.Lock()
        self.running = True
        self.paused = False
        # ---- device groups (see group_engine.GroupEngine) --------------
        # Groups are manually-assigned subsets of THIS network's devices,
        # each with its own dashboard. They share this engine's probes
        # (no duplicate pinging); the three fields below are the only
        # places the engine needs to know they exist.
        #   groups       group_id -> GroupEngine
        #   _mac_group   normalized MAC -> GroupEngine it belongs to
        #                (used to route Troubleshoot Log lines)
        #   paused_macs  normalized MACs whose group is paused — the
        #                health loop skips these devices entirely
        self.groups = {}
        self._mac_group = {}
        self.paused_macs = set()
        # Set once network_key/gateway detection has finished, so saved
        # groups (which are keyed by network_key) are only restored after
        # the key has settled.
        self._identity_event = threading.Event()
        # base_ip is virtually always passed in by callers (the network
        # picker already enumerated it via detect_networks()), so the only
        # case that ever needs get_local_ip() here is the defensive
        # fallback below.
        self.base_ip = base_ip if base_ip else ".".join(self.get_local_ip().split(".")[:-1])
        # host_ip / gateways / gateway_ip / network_key all depend on
        # subprocess calls (ipconfig/ip/netstat/arp) and, in the worst
        # case, ping probes with multi-second timeouts. Previously these
        # ran synchronously right here in __init__ — and since __init__ is
        # called directly on the UI thread once per selected network, that
        # froze the whole window for seconds (multiplied by however many
        # networks were chosen) before the dashboard could even appear.
        # Give the object cheap, instant placeholders instead, and resolve
        # the real values in the background (see _detect_network_identity,
        # kicked off from initialization_sequence which already runs on
        # its own thread). The dashboard renders immediately and swaps in
        # the real gateway/label once detection finishes a moment later.
        self.host_ip = None
        self.gateways = []
        self.gateway_ip = "DETECTING..."
        # Saved-history bucket key. base_ip alone isn't a safe identifier
        # for a *physical* network — e.g. two different ISP routers very
        # commonly both default to 192.168.1.x — so pair it with the
        # gateway's MAC (hardware-unique, unlike the subnet range) when
        # it's resolvable. Falls back to base_ip alone until the gateway
        # MAC is resolved in the background — that's strictly the old
        # "hasn't answered ARP yet" fallback behavior, so it never
        # regresses, it just doesn't disambiguate until detection finishes.
        self.network_key = self.base_ip
        self.label = label if label else f"{self.base_ip}.0/24"
        self._panel_ref = None  # set by UI after dashboard is built


        self._dhcp_cache = {}
        # Real bandwidth tracking for THIS network's own interface (see
        # get_bandwidth_snapshot). Matching the interface depends on
        # host_ip, which isn't resolved yet this early (see the comment
        # above about host_ip/gateways being deferred) — actually
        # resolved from _detect_network_identity once host_ip is known.
        self._bw_interface = None
        self._bw_baseline = None
        self._bw_session_start = datetime.now()
        # How much of the REAL (OS-counter) network total was already
        # saved from EARLIER sessions for this network, loaded once
        # _resolve_bandwidth_interface() knows network_key (see there).
        # get_bandwidth_snapshot() adds this on top of THIS session's own
        # baseline-relative delta, so the figure keeps growing across app
        # restarts instead of resetting to ~0 every time a fresh baseline
        # is captured. Zero until that load happens (or forever, if
        # psutil/the interface isn't available at all).
        self._bw_carry_sent = 0.0
        self._bw_carry_recv = 0.0
        # Running ESTIMATED total across every device ever attributed to
        # this network — the "TOTAL NETWORK CONSUMPTION" figure the UI
        # shows. Deliberately its own monotonic counter rather than a
        # live sum of self.devices' current _bw_estimated_bytes: summing
        # on the fly meant clearing one device's own total (which zeroes
        # just that device's bucket, by design) made this network-wide
        # figure appear to shrink too, even though nothing about the
        # network's actual traffic changed. This is incremented by the
        # exact same delta_bytes at the same moment each device's own
        # estimate grows (see update_health), so it always reflects
        # everything ever counted, whether or not any one device's own
        # total was later reset. Loaded from its saved value once
        # network_key is known — see _detect_network_identity.
        self._bw_network_estimated_bytes = 0.0
        # Throttles how often this engine pushes devices' running
        # bandwidth totals into bandwidth_store's cache — see
        # _BW_FLUSH_INTERVAL_SEC and _maybe_flush_bandwidth.
        self._bw_last_flush_ts = time.time()
        # Calendar date for the last automatic midnight bandwidth reset.
        self._bw_last_reset_date = None
        # Best-effort final save so a normal app close doesn't lose the
        # most recent consumption estimate still sitting only in memory.
        # Does not run on a crash / force-kill, same limitation as any
        # other atexit-based save.
        atexit.register(self._flush_bandwidth_on_exit)
        # Same reasoning for the status History Log, now that
        # history_store also batches its disk writes instead of writing
        # on every single logged entry (see history_store's module
        # docstring) — without this, the most recent burst of entries
        # could still be sitting unsaved in memory when the app closes.
        atexit.register(history_store.flush_now)
        # Network-wide spike detection: when most/all devices degrade at
        # the same moment, that's a signal the problem is upstream (router
        # / the host's own connection) rather than any individual device.
        self.network_wide_issue = False
        self.network_wide_since = None
        self._network_wide_on_streak = 0
        self._network_wide_off_streak = 0
        # Bounded worker pool for per-device health checks (see
        # update_health). Previously every device got its own raw OS
        # thread every 2s cycle, each spawning 3+ subprocess ping calls
        # and up to ~10 TCP-connect attempts — with a handful of devices
        # that's fine, but on a busy network with 50-150+ devices it meant
        # 150-450+ subprocess spawns firing at once every cycle, which is
        # what was causing the lag/freezes/crashes on larger networks
        # (process-table exhaustion and CreateProcess overhead on Windows
        # especially). Capping concurrency here means the total in-flight
        # work stays bounded no matter how many devices are on the
        # network — extra devices queue for a free worker instead of
        # spawning yet another OS thread + subprocess burst on top of
        # everything already running.
        # 24 was a flat, permanent cap. It's exactly right for a small/
        # medium network, but on a big one (100-200+ devices) it becomes
        # the new bottleneck instead of solving one: with each device's
        # check taking ~3-4s (a handful of ping packets + TCP probes),
        # only 24 running at once meant a full pass over 150 devices took
        # ~20+ seconds instead of the intended 2s cadence, so every
        # device's readings went stale/laggy the more of them there were
        # — the exact "lag with lots of devices connected" complaint this
        # was meant to fix in the first place. _resize_health_pool below
        # grows this (still bounded, so it never regresses back to the
        # old unbounded-thread problem) to track how many devices are
        # actually on this network.
        self._pool_workers = 24
        self._health_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=self._pool_workers, thread_name_prefix="health-check"
        )
        threading.Thread(target=self.initialization_sequence, daemon=True).start()
        threading.Thread(target=self._dhcp_sniffer, daemon=True).start()
        if platform.system().lower() == "windows":
            threading.Thread(target=self._wmi_lease_poller, daemon=True).start()


    def _wmi_lease_poller(self):
        """Windows-only: poll WMI every 10s for DHCP lease hostnames.
        No admin rights needed. Falls back silently if wmi not installed."""
        try:
            import wmi
        except ImportError:
            return
        while self.running:
            try:
                w = wmi.WMI()
                for adapter in w.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    mac = getattr(adapter, "MACAddress", None)
                    ips = getattr(adapter, "IPAddress", None) or []
                    if not mac:
                        continue
                    mac = mac.replace("-", ":").lower()
                    for ip in ips:
                        if not ip or ip.startswith("127.") or ":" in ip:
                            continue
                        try:
                            hostname = socket.gethostbyaddr(ip)[0].split(".")[0]
                            if hostname and not hostname.replace(".", "").isdigit():
                                display = hostname.strip().upper()
                                with self.lock:
                                    self._dhcp_cache[mac] = display
                                updated = False
                                with self.lock:
                                    for dev in self.devices:
                                        # MAC only: IP is reassigned by DHCP over
                                        # time, so matching on IP alone can rename
                                        # (or wrongly re-identify) a completely
                                        # different physical device that happens
                                        # to hold this IP now. MAC is the one
                                        # identifier that's actually stable.
                                        if dev.mac == mac:
                                            dev.name = display
                                            updated = True
                                if updated:
                                    self.ui.after(0, lambda: self.ui.request_panel_refresh(self))
                        except Exception:
                            pass
            except Exception:
                pass
            time.sleep(10)


    def _dhcp_sniffer(self):
        """Passively sniff DHCP traffic on UDP port 67/68 and extract
        the hostname (Option 12) and vendor class (Option 60) that devices
        send when requesting an IP — the exact same data the router stores.


        Works on all platforms:
          - Linux/macOS: raw AF_PACKET / AF_INET socket (needs no installs)
          - Windows:     UDP recvfrom on port 68 (best-effort; raw needs Npcap)


        Populates self._dhcp_cache[ip] and self._dhcp_cache[mac] so
        resolve_hostname can check it as Layer 0.
        """
        is_win = platform.system().lower() == "windows"
        is_mac = platform.system().lower() == "darwin"


        def _parse_dhcp(data):
            """Parse a raw DHCP packet and return (mac, requested_ip, hostname, vendor).
            Returns None if the packet is not a valid DHCP request."""
            if len(data) < 240:
                return None
            # DHCP magic cookie at offset 236: 0x63825363
            if data[236:240] != b'\x63\x82\x53\x63':
                return None
            op = data[0]   # 1 = BOOTREQUEST (client), 2 = BOOTREPLY (server)
            if op != 1:
                return None


            # Client MAC address: bytes 28-33 (hlen=6 for Ethernet)
            hlen = data[2]
            raw_mac = data[28:28 + hlen]
            if len(raw_mac) < 6:
                return None
            mac = ":".join(f"{b:02x}" for b in raw_mac)


            # Requested IP (Option 50) or ciaddr (bytes 12-15)
            ciaddr = ".".join(str(b) for b in data[12:16])
            if ciaddr == "0.0.0.0":
                ciaddr = None


            # Parse options
            hostname   = None
            vendor     = None
            req_ip     = ciaddr
            offset     = 240
            while offset < len(data):
                opt = data[offset]
                if opt == 255:   # END
                    break
                if opt == 0:     # PAD
                    offset += 1
                    continue
                if offset + 1 >= len(data):
                    break
                length = data[offset + 1]
                val    = data[offset + 2: offset + 2 + length]
                if opt == 12:    # Hostname
                    try:
                        hostname = val.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                elif opt == 50:  # Requested IP Address
                    if len(val) == 4:
                        req_ip = ".".join(str(b) for b in val)
                elif opt == 60:  # Vendor Class Identifier
                    try:
                        vendor = val.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        pass
                offset += 2 + length


            if not hostname:
                return None
            return mac, req_ip, hostname, vendor


        def _store(mac, ip, hostname, vendor=None):
            """Store name in dhcp_cache keyed by MAC."""
            name = hostname.strip()
            if not name or len(name) < 2:
                return
            display = name.upper()
            with self.lock:
                if mac:
                    self._dhcp_cache[mac] = display
                if ip and ip != "0.0.0.0":
                    self._dhcp_cache[ip] = display
            # Retroactively update any already-discovered device — DHCP always wins.
            # MAC only: `mac` is always known here (extracted straight from the
            # DHCP packet's chaddr field), so there's no case where an IP-only
            # fallback is actually needed — and matching by IP alone is
            # dangerous, since DHCP can hand this exact IP to a different
            # physical device later. Matching on it would silently rename that
            # new device to the old one's hostname, or even overwrite its MAC
            # (merging two different devices' identities into one).
            updated = False
            with self.lock:
                for dev in self.devices:
                    if mac and dev.mac == mac:
                        dev.name = display
                        updated = True
            if updated:
                self.ui.after(0, lambda: self.ui.request_panel_refresh(self))


        def _listen_on_port(port):
            """Bind a UDP broadcast socket to the given port and feed
            packets into _parse_dhcp / _store.  Returns when self.running
            becomes False or the socket cannot be opened."""
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except Exception:
                        pass
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.bind(("0.0.0.0", port))
                s.settimeout(2.0)
                while self.running:
                    try:
                        data, addr = s.recvfrom(4096)
                        result = _parse_dhcp(data)
                        if result:
                            mac, ip, hostname, vendor = result
                            _store(mac, ip or addr[0], hostname, vendor)
                    except socket.timeout:
                        continue
                    except Exception:
                        continue
                s.close()
            except Exception:
                pass


        # On all platforms try port 67 first (DHCP server port — not owned
        # by any OS service, so binding works without special permissions on
        # Windows too).  Port 68 is the DHCP client port; on Windows it is
        # owned by the system DHCP client service so binding fails silently.
        # We run both listeners in parallel threads so neither blocks the other.
        t67 = threading.Thread(target=_listen_on_port, args=(67,), daemon=True)
        t67.start()


        # Port 68 works on Linux/macOS (with SO_REUSEPORT) to catch client
        # requests.  On Windows it will fail to bind — _listen_on_port handles
        # that gracefully via the outer except.
        if not is_win:
            t68 = threading.Thread(target=_listen_on_port, args=(68,), daemon=True)
            t68.start()
            t68.join()


        t67.join()


    def get_gateways(self):
        """Return all gateway IPs that belong to this engine's subnet.


        Runs every detection method on every platform so Wi-Fi, Ethernet,
        VPNs and future adapter types all work.  Returns a list ordered
        best-first by metric.  Never raises — returns [] on total failure.
        """
        base    = getattr(self, "base_ip", None)
        is_win  = platform.system().lower() == "windows"
        is_mac  = platform.system().lower() == "darwin"
        found   = {}   # ip -> metric (lower = better)


        def _in_subnet(ip):
            if not base or not ip:
                return False
            try:
                return ip.rsplit(".", 1)[0] == base
            except Exception:
                return False


        def _ip_ok(ip):
            if not ip:
                return False
            bad = ("127.", "169.254.", "224.", "240.", "::")
            return ip != "0.0.0.0" and not any(ip.startswith(b) for b in bad)


        def _add(ip, metric=9999):
            ip = (ip or "").strip()
            if _ip_ok(ip) and _in_subnet(ip):
                if ip not in found or metric < found[ip]:
                    found[ip] = metric


        # ── METHOD 1: Windows — route print + ipconfig ───────────────────────
        if is_win:
            # 1a: route print 0.0.0.0  (covers Ethernet + Wi-Fi default routes)
            try:
                r = _run(["route", "print", "0.0.0.0"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        gw, iface = parts[2], parts[3]
                        if gw in ("On-link", "0.0.0.0"):
                            continue
                        try:
                            metric = int(parts[4])
                        except ValueError:
                            metric = 9999
                        _add(gw, metric)
                        # iface is the adapter IP — if it's our subnet,
                        # bump this gateway to higher priority
                        if _in_subnet(iface) and gw in found:
                            found[gw] = min(found[gw], metric - 1)
            except Exception:
                pass


            # 1b: ipconfig — most reliable for Wi-Fi on Windows
            try:
                r = _run(["ipconfig"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", line, re.IGNORECASE)
                    if m:
                        _add(m.group(1), 500)
            except Exception:
                pass


        # ── METHOD 2: Linux — ip route show ──────────────────────────────────
        if not is_win and not is_mac:
            try:
                r = _run(["ip", "route", "show"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if not parts:
                        continue
                    # "default via <gw> dev <dev> [proto X] [metric N] [src <ip>]"
                    if parts[0] == "default" and "via" in parts:
                        gw = parts[parts.index("via") + 1]
                        metric = 9999
                        if "metric" in parts:
                            try:
                                metric = int(parts[parts.index("metric") + 1])
                            except (ValueError, IndexError):
                                pass
                        _add(gw, metric)
                    # "<subnet>/prefix via <gw> ..." — catches per-interface routes
                    elif "/" in parts[0] and "via" in parts:
                        net = parts[0].split("/")[0]
                        if _in_subnet(net):
                            gw = parts[parts.index("via") + 1]
                            _add(gw, 2000)
            except Exception:
                pass


        # ── METHOD 3: macOS — netstat -rn -f inet ────────────────────────────
        if is_mac:
            try:
                r = _run(["netstat", "-rn", "-f", "inet"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    dest, gw = parts[0], parts[1]
                    if dest in ("default", "0.0.0.0/0"):
                        _add(gw, 1000)
                    # Per-subnet route: "192.168.1/24  192.168.1.1  ..."
                    elif "/" in dest:
                        net = dest.split("/")[0]
                        # macOS shortens octets: "192.168.1" instead of "192.168.1.0"
                        if base and (net == base or net.startswith(base + ".")):
                            _add(gw, 1500)
            except Exception:
                pass


        # ── METHOD 4: netstat -rn (Linux fallback when `ip` is unavailable) ──
        if not is_win and not is_mac:
            try:
                r = _run(["netstat", "-rn"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    parts = line.split()
                    # Linux format: Destination Gateway Genmask Flags MSS Window irtt Iface
                    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "default"):
                        _add(parts[1], 3000)
                    # Also match subnet rows whose destination is our base
                    elif len(parts) >= 2 and _in_subnet(parts[0]):
                        _add(parts[1], 3500)
            except Exception:
                pass


        # ── METHOD 5: /proc/net/route (Linux kernel table — always present) ──
        if not is_win and not is_mac:
            try:
                with open("/proc/net/route") as f:
                    for line in f.readlines()[1:]:   # skip header
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        dest_hex = parts[1]
                        gw_hex   = parts[2]
                        flags    = int(parts[3], 16)
                        # Flag 0x2 = RTF_GATEWAY, dest 0x0 = default route
                        if flags & 0x2:
                            def _hex_to_ip(h):
                                # Little-endian 4-byte hex
                                b = bytes.fromhex(h.zfill(8))
                                return ".".join(str(b) for b in reversed(b))
                            gw = _hex_to_ip(gw_hex)
                            metric = 4000 if dest_hex != "00000000" else 1000
                            _add(gw, metric)
            except Exception:
                pass


        # ── METHOD 6: ARP heuristic — .1 and .254 (all platforms) ───────────
        # Ping timeout: Windows -w is ms, Linux/macOS -W is seconds (use 1s = safe minimum)
        if base:
            ping_timeout = ("500" if is_win else "1")
            for suffix in ("1", "254"):
                candidate = f"{base}.{suffix}"
                if candidate not in found:
                    try:
                        r = _run(
                            ["ping",
                             "-n" if is_win else "-c", "1",
                             "-w" if is_win else "-W", ping_timeout,
                             candidate],
                            capture_output=True, timeout=3
                        )
                        if r.returncode == 0:
                            _add(candidate, 8000)
                    except Exception:
                        pass


        ordered = sorted(found.items(), key=lambda x: x[1])
        return [ip for ip, _ in ordered]


    def get_gateway_ip(self):
        """Backwards-compatible single-gateway accessor.
        Returns the best gateway for this subnet, or 'UNKNOWN'."""
        gws = self.get_gateways()
        return gws[0] if gws else "UNKNOWN"


    def _resolve_gateway_mac(self, gateway_ip):
        """Best-effort MAC lookup for the gateway IP, via the OS ARP table
        (same source discover_devices() already reads). Two independent
        physical networks (e.g. two different ISP routers, or a home
        network and a client site) very commonly reuse the same default
        subnet, like 192.168.1.x or 192.168.0.x — but they essentially
        never share a gateway MAC, since that's burned into the router's
        hardware at the factory. Pairing base_ip with this MAC is what
        keeps their saved histories from colliding.

        Returns None if it can't be resolved yet (e.g. ARP cache hasn't
        seen the gateway respond yet, right after startup) — callers
        should fall back to base_ip alone in that case, same as before
        this existed."""
        if not gateway_ip or gateway_ip == "UNKNOWN":
            return None
        try:
            # -n skips the reverse-DNS lookup arp -a would otherwise do for
            # every cached entry (which can hang if DNS is slow/unreachable)
            # and the explicit timeout is a second line of defense.
            arp_cmd = ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-an"]
            output = _run(arp_cmd, capture_output=True, text=True, timeout=3).stdout
            is_win = platform.system().lower() == "windows"
            for line in output.splitlines():
                mac = None
                if is_win:
                    parts = line.split()
                    if len(parts) < 3 or parts[0] != gateway_ip:
                        continue
                    mac = parts[1].replace("-", ":")
                else:
                    if gateway_ip not in line or "at" not in line:
                        continue
                    mac_match = re.search(r"at\s+([0-9a-fA-F:]+)", line)
                    if not mac_match:
                        continue
                    mac = mac_match.group(1)
                if not mac:
                    continue
                mac = ":".join(part.zfill(2) for part in mac.split(":"))
                if mac and mac != "ff:ff:ff:ff:ff:ff" and mac != "00:00:00:00:00:00":
                    return mac
        except Exception:
            pass
        return None


    def _all_local_ips(self):
        """Return every non-loopback, non-link-local IPv4 address currently
        assigned to ANY local interface (WiFi, Ethernet, VPN, etc.) — not
        just the OS's single "default route" one that get_local_ip()
        returns. This is what lets each engine check on its OWN specific
        subnet independently, instead of every engine converging on
        whichever interface happens to be the primary one."""
        is_win = platform.system().lower() == "windows"
        is_mac = platform.system().lower() == "darwin"
        ips = []

        def _add(ip):
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.append(ip)

        if is_win:
            try:
                r = _run(["ipconfig"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"IPv4.*?:\s*((\d+\.){3}\d+)", line)
                    if m:
                        _add(m.group(1))
            except Exception:
                pass
        elif is_mac:
            for iface in ("en0", "en1", "en2", "en3", "utun0", "bridge0"):
                try:
                    r = _run(["ipconfig", "getifaddr", iface],
                             capture_output=True, text=True, timeout=2)
                    _add(r.stdout.strip())
                except Exception:
                    pass
        else:
            try:
                r = _run(["ip", "addr", "show"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"inet\s+((\d+\.){3}\d+)", line)
                    if m:
                        _add(m.group(1))
            except Exception:
                pass

        return ips

    def _local_ip_on_subnet(self, base_ip):
        """Return THIS host's own IP address that belongs to `base_ip`
        (e.g. "192.168.1"), or None if no local interface currently has
        one. Never falls back to some other subnet's address — that's
        the whole point: it keeps each monitored network independent
        instead of letting one engine drift onto another's range."""
        if not base_ip:
            return None
        for ip in self._all_local_ips():
            if ip.startswith(base_ip + "."):
                return ip
        return None

    def get_local_ip(self):
        is_win = platform.system().lower() == "windows"
        is_mac = platform.system().lower() == "darwin"


        # Method 1: UDP socket trick (works on all platforms, needs no internet)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass


        # Method 2a: Windows — ipconfig
        if is_win:
            try:
                result = _run(["ipconfig"], capture_output=True, text=True)
                for line in result.stdout.splitlines():
                    m = re.search(r"IPv4.*?:\s*((\d+\.){3}\d+)", line)
                    if m:
                        ip = m.group(1)
                        if not ip.startswith("127.") and not ip.startswith("169."):
                            return ip
            except Exception:
                pass


        # Method 2b: macOS — ipconfig getifaddr (one call per common interface)
        if is_mac:
            for iface in ("en0", "en1", "en2", "utun0", "bridge0"):
                try:
                    r = _run(["ipconfig", "getifaddr", iface],
                             capture_output=True, text=True, timeout=2)
                    ip = r.stdout.strip()
                    if ip and not ip.startswith("127.") and not ip.startswith("169."):
                        return ip
                except Exception:
                    pass


        # Method 2c: Linux — ip addr show
        if not is_win and not is_mac:
            try:
                r = _run(["ip", "addr", "show"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"inet\s+((\d+\.){3}\d+)", line)
                    if m:
                        ip = m.group(1)
                        if not ip.startswith("127.") and not ip.startswith("169."):
                            return ip
            except Exception:
                pass


        # Method 3: ifconfig (macOS/Linux/BSD universal fallback)
        if not is_win:
            try:
                r = _run(["ifconfig"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"inet\s+((\d+\.){3}\d+)", line)
                    if m:
                        ip = m.group(1)
                        if not ip.startswith("127.") and not ip.startswith("169."):
                            return ip
            except Exception:
                pass


        return "127.0.0.1"


    def _detect_network_identity(self):
        """Resolve host_ip / gateways / gateway_ip / network_key.

        Moved out of __init__ so constructing an engine is instant and
        never blocks the caller's thread (typically the UI thread) — see
        the comment in __init__ for why. Runs at the start of
        initialization_sequence, which already executes on its own daemon
        thread, so all the subprocess/ping-heavy work below happens off
        the UI thread.
        """
        primary_ip = self.get_local_ip()
        # Prefer the local IP that actually sits on THIS engine's subnet
        # (relevant when the host has multiple adapters/networks at once
        # and this engine isn't watching the "default route" one) — fall
        # back to the primary IP only if no interface on this subnet was
        # found yet (e.g. still coming up during init_sequence).
        self.host_ip = self._local_ip_on_subnet(self.base_ip) or primary_ip
        self.gateways   = self.get_gateways()          # list, ordered best-first
        self.gateway_ip = self.gateways[0] if self.gateways else "UNKNOWN"
        gw_mac = self._resolve_gateway_mac(self.gateway_ip)
        self.network_key = f"{self.base_ip}::{gw_mac}" if gw_mac else self.base_ip
        # Resume the ESTIMATED network-wide total from an earlier session
        # for this same network, same "don't reset to 0 on restart"
        # treatment as every other saved bandwidth figure. Independent of
        # psutil/interface resolution below, since it's built purely from
        # this app's own per-device speed probes, not OS interface
        # counters.
        with self.lock:
            self._bw_network_estimated_bytes = bandwidth_store.load_network_estimated_total(
                self.network_key
            )
        self._resolve_bandwidth_interface()
        # Apply the daily reset immediately on startup if this network has
        # not yet been reset for today, rather than waiting for a health cycle.
        self._reset_bandwidth_at_midnight_if_needed()
        # Push the freshly-resolved gateway onto the dashboard (it was
        # showing "DETECTING..." until now).
        self.ui.after(0, lambda: self.ui.request_panel_refresh(self))

    def _resolve_bandwidth_interface(self):
        """Match this engine's network (self.host_ip / self.base_ip) to
        one local NIC name, so get_bandwidth_snapshot() reads THAT
        interface's own byte counters instead of the whole machine's
        combined total. That distinction matters as soon as more than one
        network is being monitored at once (each would otherwise report
        the same combined number), and it also keeps out interfaces that
        have nothing to do with this network, like a VPN adapter or a
        second NIC on a different subnet. Records a baseline reading at
        the moment the interface is found, so later snapshots can report
        "how much since monitoring started" rather than the interface's
        all-time total (which includes traffic from before this app even
        opened)."""
        if not _PSUTIL_AVAILABLE:
            return
        try:
            target_ip = self.host_ip
            match = None
            for name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == target_ip:
                        match = name
                        break
                if match:
                    break
            if not match:
                return
            counters = psutil.net_io_counters(pernic=True).get(match)
            if counters is None:
                return
            with self.lock:
                self._bw_interface = match
                self._bw_baseline = counters
                self._bw_session_start = datetime.now()
                # Resume from whatever was saved for THIS network in an
                # earlier session, instead of starting the displayed
                # total back at zero every time the app (or this
                # network's monitoring) restarts. network_key is already
                # set by the time this runs (_detect_network_identity
                # sets it just before calling this method).
                carry = bandwidth_store.load_network_real_total(self.network_key)
                self._bw_carry_sent = carry["sent"]
                self._bw_carry_recv = carry["recv"]
        except Exception:
            pass

    def initialization_sequence(self):
        self.ui.update_status("SYSTEM INITIALIZING...", "#808080", "black")
        self.add_troubleshoot_log("INITIALIZING NETWORK-BASED MAPPING...")
        try:
            self._detect_network_identity()
        finally:
            self._identity_event.set()
        self.proactive_scan()
        self.ui.update_status("MONITOR ACTIVE", "#00CC66", "black")
        # Run monitor and continuous background scan in parallel
        threading.Thread(target=self.monitor_network, daemon=True).start()
        threading.Thread(target=self.continuous_scan, daemon=True).start()
        # After devices are discovered, try to resolve any still showing DEVICE-XXXXXX
        threading.Thread(target=self._background_name_refresh, daemon=True).start()


    def _background_name_refresh(self):
        """Resolves names of already-connected devices without requiring them
        to reconnect. Uses four broadcast/multicast methods that prompt all
        devices to announce themselves, then falls back to per-device queries."""
        time.sleep(4)  # let initial device list populate first


        # ── Shared name store ─────────────────────────────────────────────────
        # ip -> name, collected from all broadcast methods
        discovered = {}
        discovered_lock = threading.Lock()


        def _store_name(ip, name):
            if not name or len(name) < 2:
                return
            bad = {"local", "arpa", "in-addr", "ip6", "tcp", "udp",
                   "mdns", "dns", "gateway", "localhost", "broadcasthost"}
            if name.lower() in bad or name.replace(".", "").isdigit():
                return
            with discovered_lock:
                discovered[ip] = name.strip().upper()


        # ── METHOD 1: mDNS service discovery broadcast ────────────────────────
        # Sends _services._dns-sd._udp.local query to 224.0.0.251 — prompts ALL
        # mDNS-capable devices (phones, Macs, Android, smart devices) to announce
        def _mdns_broadcast():
            try:
                def encode_name(name):
                    enc = b""
                    for part in name.split("."):
                        enc += bytes([len(part)]) + part.encode()
                    return enc + b"\x00"


                # Query _services._dns-sd._udp.local (PTR) — all devices respond
                query = (
                    b"\x00\x00"  # tx id
                    b"\x00\x00"  # flags (standard query)
                    b"\x00\x01"  # 1 question
                    b"\x00\x00\x00\x00\x00\x00"
                    + encode_name("_services._dns-sd._udp.local")
                    + b"\x00\x0c"  # PTR
                    + b"\x00\x01"  # IN
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.settimeout(3.0)
                sock.sendto(query, ("224.0.0.251", 5353))


                deadline = time.time() + 3.0
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(4096)
                        ip = addr[0]
                        if not ip.startswith(self.base_ip + "."):
                            continue
                        # Pull any readable label from the response as device name
                        off = 12
                        # skip questions
                        qdcount = (data[4] << 8) | data[5]
                        for _ in range(qdcount):
                            while off < len(data):
                                n = data[off]
                                if n == 0: off += 1; break
                                if n & 0xc0 == 0xc0: off += 2; break
                                off += 1 + n
                            off += 4
                        # read answers
                        ancount = (data[6] << 8) | data[7]
                        for _ in range(ancount):
                            if off >= len(data): break
                            labels = []
                            ptr_off = off
                            while ptr_off < len(data):
                                n = data[ptr_off]
                                if n == 0: ptr_off += 1; break
                                if n & 0xc0 == 0xc0:
                                    ptr = ((n & 0x3f) << 8) | data[ptr_off + 1]
                                    ptr_off = ptr; continue
                                labels.append(data[ptr_off+1:ptr_off+1+n].decode("utf-8", errors="ignore"))
                                ptr_off += 1 + n
                            if labels:
                                first = labels[0].strip()
                                bad = {"local","arpa","in-addr","_services","_dns-sd","_udp","_tcp",""}
                                if first and first.lower() not in bad and not first.startswith("_"):
                                    _store_name(ip, first)
                            # skip to next record
                            while off < len(data):
                                n = data[off]
                                if n == 0: off += 1; break
                                if n & 0xc0 == 0xc0: off += 2; break
                                off += 1 + n
                            if off + 10 > len(data): break
                            off += 8  # type, class, TTL
                            rdlen = (data[off] << 8) | data[off+1]
                            off += 2 + rdlen
                    except socket.timeout:
                        break
                    except Exception:
                        continue
                sock.close()
            except Exception:
                pass


        # ── METHOD 2: mDNS per-device PTR query ──────────────────────────────
        # Sends a reverse-DNS PTR query directly to each device's IP on port 5353
        def _mdns_per_device(ip):
            try:
                def encode_name(name):
                    enc = b""
                    for part in name.split("."):
                        enc += bytes([len(part)]) + part.encode()
                    return enc + b"\x00"


                reversed_ip = ".".join(reversed(ip.split(".")))
                query_name  = f"{reversed_ip}.in-addr.arpa"
                packet = (
                    b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                    + encode_name(query_name)
                    + b"\x00\x0c\x00\x01"
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.settimeout(2.0)
                try: sock.sendto(packet, ("224.0.0.251", 5353))
                except Exception: pass
                try: sock.sendto(packet, (ip, 5353))
                except Exception: pass


                for _ in range(5):
                    try:
                        data, addr = sock.recvfrom(2048)
                        if addr[0] != ip or len(data) < 12: continue
                        ancount = (data[6] << 8) | data[7]
                        if ancount == 0: continue
                        off = 12
                        qdcount = (data[4] << 8) | data[5]
                        for _ in range(qdcount):
                            while off < len(data):
                                n = data[off]
                                if n == 0: off += 1; break
                                if n & 0xc0 == 0xc0: off += 2; break
                                off += 1 + n
                            off += 4
                        for _ in range(ancount):
                            if off + 10 > len(data): break
                            while off < len(data):
                                n = data[off]
                                if n == 0: off += 1; break
                                if n & 0xc0 == 0xc0: off += 2; break
                                off += 1 + n
                            rtype = (data[off] << 8) | data[off+1]
                            off += 8
                            rdlen = (data[off] << 8) | data[off+1]
                            off += 2
                            rdata_off = off
                            off += rdlen
                            if rtype != 12: continue
                            labels, ptr_off = [], rdata_off
                            while ptr_off < len(data):
                                n = data[ptr_off]
                                if n == 0: break
                                if n & 0xc0 == 0xc0:
                                    ptr = ((n & 0x3f) << 8) | data[ptr_off+1]
                                    ptr_off = ptr; continue
                                labels.append(data[ptr_off+1:ptr_off+1+n].decode("utf-8", errors="ignore"))
                                ptr_off += 1 + n
                            first = labels[0].strip() if labels else ""
                            bad = {"local","arpa","in-addr","ip6","tcp","udp",""}
                            if first and first.lower() not in bad and len(first) > 1:
                                _store_name(ip, first)
                                sock.close()
                                return
                    except Exception:
                        break
                sock.close()
            except Exception:
                pass


        # ── METHOD 3: NetBIOS broadcast (all platforms) ───────────────────────
        # Sends a UDP broadcast to 255.255.255.255:137 — Windows machines and
        # many NAS/printers respond with their NetBIOS name immediately
        def _netbios_broadcast():
            try:
                # NetBIOS Name Service query — wildcard "*" broadcast
                packet = (
                    b"\xaa\xbb"          # tx id
                    b"\x01\x10"          # flags: broadcast query
                    b"\x00\x01"          # 1 question
                    b"\x00\x00\x00\x00\x00\x00"
                    b"\x20"              # name length (32)
                    b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # encoded "*" wildcard
                    b"\x00"
                    b"\x00\x21"          # type: NB (NetBIOS name)
                    b"\x00\x01"          # class: IN
                )
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(3.0)
                sock.bind(("", 0))
                sock.sendto(packet, ("255.255.255.255", 137))


                deadline = time.time() + 3.0
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(1024)
                        ip = addr[0]
                        if not ip.startswith(self.base_ip + "."): continue
                        if len(data) < 57: continue
                        # NetBIOS name is at offset 56, 16 bytes, space-padded
                        raw = data[56:72].decode("ascii", errors="ignore").strip()
                        if raw and len(raw) > 1 and not raw.replace(" ", "").isdigit():
                            _store_name(ip, raw.strip())
                    except socket.timeout:
                        break
                    except Exception:
                        continue
                sock.close()
            except Exception:
                pass


        # ── METHOD 4: UPnP/SSDP broadcast ────────────────────────────────────
        # Sends M-SEARCH to 239.255.255.250:1900 — smart TVs, printers,
        # Windows PCs, NAS devices, routers all respond with their friendly name
        def _ssdp_broadcast():
            try:
                msg = (
                    "M-SEARCH * HTTP/1.1\r\n"
                    "HOST: 239.255.255.250:1900\r\n"
                    "MAN: \"ssdp:discover\"\r\n"
                    "MX: 3\r\n"
                    "ST: ssdp:all\r\n\r\n"
                ).encode()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.settimeout(3.0)
                sock.sendto(msg, ("239.255.255.250", 1900))


                deadline = time.time() + 3.0
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(4096)
                        ip = addr[0]
                        if not ip.startswith(self.base_ip + "."): continue
                        text = data.decode("utf-8", errors="ignore")
                        # Extract friendly name from SERVER or USN headers
                        name = None
                        for line in text.splitlines():
                            line_l = line.lower()
                            if line_l.startswith("server:"):
                                val = line.split(":", 1)[1].strip()
                                # SERVER often looks like "OS/ver UPnP/1.0 DeviceName/ver"
                                parts = val.split()
                                for p in parts:
                                    if "/" in p:
                                        candidate = p.split("/")[0].strip()
                                        skip = {"upnp","http","os","linux","windows",
                                                "unix","microsoft","intel","","1"}
                                        if candidate.lower() not in skip and len(candidate) > 2:
                                            name = candidate
                                            break
                            if line_l.startswith("usn:") and not name:
                                val = line.split(":", 1)[1].strip()
                                # USN: uuid:xxxx::urn:schemas-upnp-org:device:DeviceType:1
                                if "device:" in val.lower():
                                    parts = val.lower().split("device:")
                                    if len(parts) > 1:
                                        candidate = parts[1].split(":")[0].strip().title()
                                        if candidate and len(candidate) > 2:
                                            name = candidate
                        if name:
                            _store_name(ip, name)
                    except socket.timeout:
                        break
                    except Exception:
                        continue
                sock.close()
            except Exception:
                pass


        # ── METHOD 5: Reverse DNS per-device ─────────────────────────────────
        def _dns_query(ip):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                short = hostname.split(".")[0].strip()
                skip = ["mdns", "dns", "iot", "switch", "hub", "bridge",
                        "gateway", "service", "localhost", "broadcasthost"]
                if short and not any(s in short.lower() for s in skip) and len(short) > 1:
                    _store_name(ip, short)
            except Exception:
                pass


        # ── METHOD 6: NetBIOS per-device (nbtstat) — Windows only ────────────
        def _netbios_per_device(ip):
            if platform.system().lower() != "windows":
                return
            try:
                result = _run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    if "<00>" in line and "GROUP" not in line:
                        name = line.split()[0].strip()
                        if name and len(name) > 1:
                            _store_name(ip, name)
                            return
            except Exception:
                pass


        # ── RUN ALL BROADCAST METHODS FIRST (parallel) ───────────────────────
        broadcast_threads = [
            threading.Thread(target=_mdns_broadcast,   daemon=True),
            threading.Thread(target=_netbios_broadcast, daemon=True),
            threading.Thread(target=_ssdp_broadcast,   daemon=True),
        ]
        for t in broadcast_threads: t.start()
        for t in broadcast_threads: t.join(timeout=4)


        # ── APPLY BROADCAST RESULTS ───────────────────────────────────────────
        with self.lock:
            for dev in self.devices:
                if dev.ip in discovered and dev.name.startswith("DEVICE-"):
                    name = discovered[dev.ip]
                    dev.name = name
                    self._dhcp_cache[dev.mac] = name
        self.ui.after(0, lambda: self.ui.request_panel_refresh(self))


        # ── PER-DEVICE QUERIES for any still unnamed ──────────────────────────
        def refresh_device(dev):
            if not dev.name.startswith("DEVICE-"):
                return
            ip, mac = dev.ip, dev.mac
            _mdns_per_device(ip)
            _dns_query(ip)
            _netbios_per_device(ip)
            with discovered_lock:
                name = discovered.get(ip)
            if name:
                with self.lock:
                    dev.name = name
                    self._dhcp_cache[mac] = name
                self.ui.after(0, lambda: self.ui.request_panel_refresh(self))


        with self.lock:
            targets = [d for d in self.devices if d.name.startswith("DEVICE-")]
        threads = [threading.Thread(target=refresh_device, args=(dev,), daemon=True)
                   for dev in targets]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)


        # ── SECOND PASS 30s later for slow responders ─────────────────────────
        time.sleep(30)
        # Re-run broadcasts
        broadcast_threads = [
            threading.Thread(target=_mdns_broadcast,    daemon=True),
            threading.Thread(target=_netbios_broadcast, daemon=True),
            threading.Thread(target=_ssdp_broadcast,    daemon=True),
        ]
        for t in broadcast_threads: t.start()
        for t in broadcast_threads: t.join(timeout=4)


        with self.lock:
            targets = [d for d in self.devices if d.name.startswith("DEVICE-")]
        threads = [threading.Thread(target=refresh_device, args=(dev,), daemon=True)
                   for dev in targets]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)


    def monitor_network(self):
        threading.Thread(target=self._discovery_loop, daemon=True).start()
        threading.Thread(target=self._health_loop, daemon=True).start()


    def _discovery_loop(self):
        # Same reasoning as the stagger in _health_loop — without it,
        # every monitored network's arp -a poll lands on the same 0.5s
        # boundary too.
        initial_offset = ((self._stagger_slot - 1) % 5) * 0.1 + random.uniform(0, 0.05)
        if initial_offset:
            time.sleep(initial_offset)
        while self.running:
            if not self.paused:
                self.discover_devices()
            time.sleep(0.5)


    def _health_loop(self):
        # Spread this engine's cadence out from every other monitored
        # network's — see _stagger_slot's comment above. With up to 5
        # networks supported, this spaces them roughly 0.4s apart across
        # the 2s cycle (slot 1 -> 0.0s, slot 2 -> 0.4s, ...), so their
        # probing bursts and UI redraws no longer all land in the same
        # instant. Small extra jitter on top so even same-slot collisions
        # (6th+ network, or two engines created in the exact same tick)
        # don't stay perfectly locked to each other either.
        initial_offset = ((self._stagger_slot - 1) % 5) * 0.4 + random.uniform(0, 0.15)
        if initial_offset:
            time.sleep(initial_offset)
        _gw_tick = 0
        while self.running:
            if not self.paused:
                # The whole per-cycle body is wrapped here on purpose: this
                # loop is this network's ONLY heartbeat. Before this fix, an
                # unhandled exception anywhere in update_health() or the
                # gateway-refresh block below would propagate straight out
                # of this while loop and silently kill this daemon thread —
                # the app itself wouldn't crash, but this one network would
                # quietly stop updating forever (frozen readings) with
                # nothing telling the user why. Catching here means one bad
                # cycle just gets logged and skipped; the loop, and this
                # network's monitoring, keep going on the next 2s tick.
                try:
                    self.update_health()
                    self._maybe_flush_bandwidth()
                except Exception as e:
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.add_troubleshoot_log(
                        f"[{ts}] HEALTH-LOOP ERROR (recovered): {e} — "
                        f"monitoring continues next cycle."
                    )
                # Refresh gateway every ~6 seconds (3 x 2s)
                _gw_tick += 1
                if _gw_tick >= 3:
                    _gw_tick = 0
                    # Same reasoning as the try/except around update_health()
                    # above: gateway detection touches the network stack
                    # (subprocess/ARP/socket calls) just like update_health
                    # does, so it deserves the same protection — one failed
                    # gateway refresh shouldn't be able to kill this thread
                    # either.
                    try:
                        # Re-check THIS engine's own subnet only — never adopt
                        # a different subnet just because it happens to be the
                        # host's current "default route" interface. Each
                        # monitored network is independent: if its adapter
                        # drops, we note that and keep waiting for it, we
                        # don't quietly start scanning some other network.
                        changed = False
                        current_host_ip = self._local_ip_on_subnet(self.base_ip)
                        if current_host_ip:
                            if current_host_ip != self.host_ip:
                                self.host_ip = current_host_ip
                                changed = True
                        elif self.host_ip is not None:
                            ts = datetime.now().strftime("%H:%M:%S")
                            self.add_troubleshoot_log(
                                f"[{ts}] {self.base_ip}.0/24 INTERFACE NOT FOUND — "
                                f"still monitoring this network, will resume once reconnected."
                            )
                            self.host_ip = None
                            changed = True


                        # Refresh full gateway list for the current subnet
                        new_gws = self.get_gateways()
                        if new_gws != self.gateways:
                            old_gw_str = ", ".join(self.gateways) if self.gateways else "UNKNOWN"
                            new_gw_str = ", ".join(new_gws)
                            ts = datetime.now().strftime("%H:%M:%S")
                            self.add_troubleshoot_log(f"[{ts}] GATEWAYS CHANGED: [{old_gw_str}] -> [{new_gw_str}]")
                            self.gateways   = new_gws
                            self.gateway_ip = new_gws[0] if new_gws else "UNKNOWN"
                            # Re-derive network_key too — if we started up
                            # before the gateway answered ARP, this is where
                            # a same-subnet collision gets disambiguated once
                            # it finally resolves. Once a gateway MAC has
                            # already been captured, don't downgrade back to
                            # base_ip-only just because a query briefly missed.
                            gw_mac = self._resolve_gateway_mac(self.gateway_ip)
                            if gw_mac:
                                self.network_key = f"{self.base_ip}::{gw_mac}"
                            changed = True
                    except Exception as e:
                        ts = datetime.now().strftime("%H:%M:%S")
                        self.add_troubleshoot_log(
                            f"[{ts}] GATEWAY-REFRESH ERROR (recovered): {e} — "
                            f"will retry on the next refresh tick."
                        )
            # 2s instead of 0.5s: matches the UI's actual refresh rate (no
            # point polling 4x faster than the screen ever updates), and
            # gives each device's readings real breathing room instead of
            # being re-pinged before the last cycle even settled — which
            # was a real source of latency noise (self-induced polling
            # contention, not the network).
            time.sleep(2)


    def continuous_scan(self):
        """Continuously pings all IPs in the subnet in small batches
        so new devices are detected within seconds of joining.


        Batch size and pacing are deliberately conservative: up to 5 of
        these loops can run at once (one per network table), each sweeping
        a full /24. Smaller batches + a slightly longer pause keep the
        combined concurrent ping-process count low across all 5 tables,
        trading a bit of "new device" detection speed for reliability and
        no lag under simultaneous multi-table load.
        """
        is_win = platform.system().lower() == "windows"
        param = "-n" if is_win else "-c"
        timeout_flag = "-w" if is_win else "-W"


        BATCH_SIZE   = 8     # was 20 — fewer concurrent ping processes per table
        BATCH_PAUSE  = 0.6   # was 0.5 — small extra breathing room per batch


        while self.running:
            # Scan BATCH_SIZE IPs at a time, cycling through the full subnet
            for batch_start in range(2, 255, BATCH_SIZE):
                if not self.running: break
                batch = range(batch_start, min(batch_start + BATCH_SIZE, 255))
                procs = []
                for i in batch:
                    target = f"{self.base_ip}.{i}"
                    p = _popen(
                        ["ping", param, "1", timeout_flag, "300", target],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    procs.append(p)
                for p in procs: p.wait()
                # After each batch, immediately check ARP for new devices
                self.discover_devices()
                time.sleep(BATCH_PAUSE)


    def discover_devices(self):
        # -n skips arp -a's reverse-DNS lookup per entry (can hang if DNS
        # is slow/unreachable) and the timeout is a second line of defense.
        arp_cmd = ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-an"]
        output = _run(arp_cmd, capture_output=True, text=True, timeout=3).stdout
        is_win = platform.system().lower() == "windows"
        candidates = []


        for line in output.splitlines():
            ip, mac = None, None


            if is_win:
                parts = line.split()
                if len(parts) < 3: continue
                if not any(t in parts[-1].lower() for t in ["dynamic", "static"]): continue
                ip = parts[0]
                mac = parts[1].replace("-", ":")
                mac = ":".join(part.zfill(2) for part in mac.split(":"))
            else:
                if "at" not in line or "incomplete" in line: continue
                ip_match = re.search(r"\((.*?)\)", line)
                mac_match = re.search(r"at\s+([0-9a-fA-F:]+)", line)
                if not ip_match or not mac_match: continue
                ip, mac = ip_match.group(1), mac_match.group(1)
                mac = ":".join(part.zfill(2) for part in mac.split(":"))


            if not ip or not mac: continue
            if not ip.startswith(self.base_ip + "."): continue
            if ip == self.host_ip: continue
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"): continue
            # Exclude the actual detected gateway(s) for this subnet (from
            # get_gateways(), via routing table / OS APIs) rather than
            # guessing off the last IP octet. A hardcoded .1/.254/.0 check
            # misses real-world gateways that don't follow that convention
            # (e.g. a phone acting as a Wi-Fi hotspot for the host device),
            # letting them wrongly show up as regular scanned devices.
            if ip in self.gateways: continue
            if ip.endswith(".0"): continue
            # Skip broadcast / null MAC addresses — these aren't real
            # devices, just artifacts of how some routers populate the
            # ARP table (e.g. ff:ff:ff:ff:ff:ff for a broadcast entry
            # that doesn't happen to end in .255, or an all-zero pad).
            if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"): continue
            # Skip if already tracked AND not permanently offline (ghost)
            existing = next((d for d in self.devices if d.ip == ip), None)
            if existing and existing.status != "Ghost": continue
            if existing and existing.status == "Ghost": continue


            candidates.append((ip, mac))


        # MAC OUI vendor lookup table
        oui_map = {
            "00:50:56": "VMware VM", "00:0c:29": "VMware VM", "00:1c:42": "Parallels VM",
            "08:00:27": "VirtualBox VM", "52:54:00": "QEMU VM",
            "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
            "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
            "18:b4:30": "Nest Device", "64:16:66": "Nest Device",
            "68:37:e9": "Amazon Echo", "44:65:0d": "Amazon Echo", "f0:27:2d": "Amazon Echo",
            "00:1a:11": "Google Device", "f4:f5:d8": "Google Device", "54:60:09": "Google Device",
            "ac:bc:32": "Apple Device", "f8:ff:c2": "Apple Device", "28:cf:da": "Apple Device",
            "00:03:93": "Apple Device", "00:0a:27": "Apple Device", "00:0a:95": "Apple Device",
            "3c:15:c2": "Samsung Device", "f4:7b:5e": "Samsung Device", "cc:07:ab": "Samsung Device",
            "00:1d:ba": "Sony Device", "30:17:c8": "Sony Device",
            "00:18:e7": "TP-Link", "50:c7:bf": "TP-Link", "b0:be:76": "TP-Link",
            "c8:d3:a3": "Huawei Device", "00:e0:fc": "Huawei Device",
            "00:50:f2": "Microsoft Device", "28:18:78": "Microsoft Device",
            "00:1b:63": "Apple AirPort", "00:1f:f3": "Apple AirPort",
            "00:1b:21": "Intel NIC", "00:21:6a": "Intel NIC",
            "e4:ce:8f": "PlayStation", "00:04:1f": "PlayStation",
            "00:1f:a7": "Xbox", "00:22:48": "Xbox",
            "00:17:f2": "Apple TV", "d8:d1:cb": "Apple TV",
            "00:0f:de": "Netgear", "a0:40:a0": "Netgear",
            "00:18:4d": "Cisco", "00:1b:54": "Cisco",
            "00:14:bf": "Linksys", "00:16:b6": "Linksys",
        }


        def resolve_hostname(ip, mac):
            """Try multiple methods to get a meaningful device name."""
            # Layer 0: DHCP hostname cache — MAC only, IP is unreliable due to DHCP reshuffling
            dhcp_name = self._dhcp_cache.get(mac)
            if dhcp_name:
                return dhcp_name


            # Layer 1: Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                short = hostname.split(".")[0].strip()
                skip = ["mdns", "dns", "iot", "switch", "hub", "bridge", "gateway",
                        "service", "localhost", "broadcasthost"]
                if short and not any(s in short.lower() for s in skip) and len(short) > 1:
                    return short.upper()
            except Exception:
                pass


            # Layer 2: mDNS — how iPhones, Androids, Macs broadcast their real name
            try:
                import struct
                mdns_ip   = "224.0.0.251"
                mdns_port = 5353


                def encode_name(name):
                    encoded = b""
                    for part in name.split("."):
                        encoded += bytes([len(part)]) + part.encode()
                    return encoded + b"\x00"


                reversed_ip = ".".join(reversed(ip.split(".")))
                query_name  = f"{reversed_ip}.in-addr.arpa"
                packet = (
                    b"\x00\x01"  # tx id
                    b"\x00\x00"  # flags
                    b"\x00\x01"  # questions
                    b"\x00\x00"  # answer RRs
                    b"\x00\x00"  # authority RRs
                    b"\x00\x00"  # additional RRs
                    + encode_name(query_name)
                    + b"\x00\x0c"  # PTR
                    + b"\x00\x01"  # IN
                )


                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.5)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                sock.sendto(packet, (mdns_ip, mdns_port))
                try:
                    sock.sendto(packet, (ip, mdns_port))
                except Exception:
                    pass


                def _skip_name(buf, off):
                    """Skip a DNS name at offset, return offset after it."""
                    while off < len(buf):
                        n = buf[off]
                        if n == 0:
                            return off + 1
                        if n & 0xc0 == 0xc0:
                            return off + 2
                        off += 1 + n
                    return off


                def _read_name(buf, off):
                    """Decode a DNS name (follows compression pointers).
                    Returns (name_string, offset_after_name)."""
                    labels = []
                    visited = set()
                    while off < len(buf):
                        if off in visited:
                            break
                        visited.add(off)
                        n = buf[off]
                        if n == 0:
                            off += 1
                            break
                        if n & 0xc0 == 0xc0:
                            ptr = ((n & 0x3f) << 8) | buf[off + 1]
                            off += 2
                            sub, _ = _read_name(buf, ptr)
                            labels.append(sub)
                            break
                        label = buf[off + 1: off + 1 + n].decode("utf-8", errors="ignore")
                        labels.append(label)
                        off += 1 + n
                    return ".".join(labels), off


                for _ in range(5):
                    try:
                        data, addr = sock.recvfrom(2048)
                        if addr[0] != ip or len(data) < 12:
                            continue


                        ancount = (data[6] << 8) | data[7]
                        if ancount == 0:
                            continue


                        # Skip the question section
                        off = 12
                        qdcount = (data[4] << 8) | data[5]
                        for _ in range(qdcount):
                            off = _skip_name(data, off)
                            off += 4   # qtype + qclass


                        # Parse answer RRs — we want TYPE PTR (12)
                        for _ in range(ancount):
                            if off >= len(data):
                                break
                            _name, off = _read_name(data, off)
                            if off + 10 > len(data):
                                break
                            rtype  = (data[off] << 8) | data[off + 1]
                            off   += 8   # skip type, class, TTL
                            rdlen  = (data[off] << 8) | data[off + 1]
                            off   += 2
                            rdata_off = off
                            off   += rdlen


                            if rtype != 12:   # not PTR
                                continue


                            ptr_name, _ = _read_name(data, rdata_off)
                            # PTR looks like "Johns-iPhone.local" — take first label
                            first = ptr_name.split(".")[0].strip()
                            bad = {"local", "arpa", "in-addr", "ip6", "tcp", "udp", ""}
                            if (first
                                    and first.lower() not in bad
                                    and len(first) > 1
                                    and not first.replace("-", "").replace("_", "").isdigit()):
                                sock.close()
                                return first.upper()
                    except Exception:
                        break
                sock.close()
            except Exception:
                pass


            # Layer 3: NetBIOS (Windows machines)
            if platform.system().lower() == "windows":
                try:
                    result = _run(
                        ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3
                    )
                    for line in result.stdout.splitlines():
                        if "<00>" in line and "GROUP" not in line:
                            name = line.split()[0].strip()
                            if name and len(name) > 1:
                                return name.upper()
                except Exception:
                    pass


            # Layer 4: MAC OUI vendor lookup
            mac_prefix = mac[:8].lower()
            for prefix, vendor in oui_map.items():
                if mac_prefix == prefix.lower():
                    return vendor


            # Layer 5: MAC suffix fallback
            suffix = mac.replace(":", "")[-6:].upper()
            return f"DEVICE-{suffix}"


        def process_candidate(ip, mac):
            name = None


            # Layer 0: MAC match in dhcp_cache (known device this session)
            name = self._dhcp_cache.get(mac)


            # Layer 1+: active resolution (DNS, mDNS, NetBIOS, OUI)
            if not name:
                name = resolve_hostname(ip, mac)
            if not name:
                name = f"DEVICE-{mac.replace(':', '')[-6:].upper()}"


            with self.lock:
                # MAC is this device's real, stable identity — its IP is not,
                # since DHCP can (and routinely does) hand it a new one on
                # lease renewal, a router reboot, or a reconnect. Matching on
                # IP alone meant a device that simply got a new IP looked like
                # a brand-new device: a duplicate row appeared for it, its old
                # row froze and eventually read "Offline" (a false alert for a
                # device that's actually fine), and its latency/jitter/loss/
                # bandwidth history split across the two objects instead of
                # staying continuous for the one physical machine. Matching by
                # MAC first — and simply updating the IP on the existing
                # device when it's changed — keeps one device meaning one row,
                # with its history intact, across DHCP re-leases.
                existing = next((dev for dev in self.devices if dev.mac == mac), None)
                if existing is not None:
                    if existing.ip != ip:
                        existing.ip = ip
                else:
                    dev = NetworkDevice(ip, mac)
                    dev.name = name
                    # Restore this device's saved history (survives the app
                    # being closed, updated, or reinstalled) so the History
                    # Log doesn't start empty every time it's rediscovered.
                    dev.status_history = list(history_store.load_for_mac(self.network_key, mac))[-100:]
                    # Same idea for its running bandwidth consumption total
                    # (see bandwidth_store) — otherwise this would silently
                    # reset to 0 every time the app restarts and rediscovers
                    # the device, even though it's the same physical device.
                    dev._bw_estimated_bytes = bandwidth_store.load_for_mac(self.network_key, mac)
                    self.devices.append(dev)


            # Cache real names by MAC for instant recall within this session
            generic = (name.startswith("DEVICE-") or name in (
                "Apple Device", "Samsung Device", "Google Device",
                "Huawei Device", "Microsoft Device", "TP-Link",
                "VMware VM", "Parallels VM", "VirtualBox VM", "QEMU VM",
                "Raspberry Pi", "Philips Hue", "Nest Device", "Amazon Echo",
                "Sony Device", "Apple AirPort", "Intel NIC", "PlayStation",
                "Xbox", "Apple TV", "Netgear", "Cisco", "Linksys",
            ))
            if not generic:
                with self.lock:
                    self._dhcp_cache[mac] = name


            self.ui.after(0, lambda: self.ui.request_panel_refresh(self))


        threads = [threading.Thread(target=process_candidate, args=(ip, mac), daemon=True) for ip, mac in candidates]
        for t in threads: t.start()
        for t in threads: t.join(timeout=3)


    def _resize_health_pool(self, device_count):
        """Grow (never shrink) the health-check worker pool to keep a full
        pass over every device roughly within one ~2s cadence, instead of
        the old flat 24-worker cap that made larger networks fall further
        and further behind the more devices they had. One worker per ~2
        devices, floor of 24 (small networks keep today's behavior exactly),
        capped at 96 so a very large network still can't spawn an unbounded
        number of concurrent OS threads/subprocesses — it just means those
        networks settle for a slightly slower per-device cadence instead of
        overwhelming the host, which is the same tradeoff the original cap
        was making, just at a size that actually fits big networks too.
        Only rebuilds the executor when the target actually grows; in-flight
        tasks on the old pool are left to finish on their own (shutdown
        with wait=False), so this never stalls a cycle to resize.
        """
        target = max(24, min(96, (device_count + 1) // 2))
        if target <= self._pool_workers:
            return
        old_pool = self._health_pool
        self._pool_workers = target
        self._health_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=target, thread_name_prefix="health-check"
        )
        old_pool.shutdown(wait=False)

    def _reset_bandwidth_at_midnight_if_needed(self):
        """Reset all bandwidth consumption figures once per local calendar day.

        This resets the saved and in-memory ESTIMATED network total, every
        device's saved/in-memory estimate, and the REAL interface total. The
        interface baseline is moved to the current counters so traffic from
        before midnight cannot leak into the new day's total.
        """
        network_key = getattr(self, "network_key", None)
        if not network_key:
            return
        today = datetime.now().date().isoformat()
        if self._bw_last_reset_date == today:
            return
        try:
            if not bandwidth_store.daily_reset_needed(network_key, today):
                self._bw_last_reset_date = today
                return

            # Clear persisted per-device + network estimated/real totals.
            bandwidth_store.clear_network(network_key)
            bandwidth_store.mark_daily_reset(network_key, today)

            with self.lock:
                for dev in self.devices:
                    dev._bw_estimated_bytes = 0.0
                self._bw_network_estimated_bytes = 0.0
                self._bw_carry_sent = 0.0
                self._bw_carry_recv = 0.0

                # Start a fresh REAL-interface baseline from this exact moment.
                if _PSUTIL_AVAILABLE and self._bw_interface:
                    try:
                        counters = psutil.net_io_counters(pernic=True).get(self._bw_interface)
                        if counters is not None:
                            self._bw_baseline = counters
                    except Exception:
                        pass

                self._bw_last_reset_date = today
        except Exception:
            # A reset failure must never stop network health monitoring.
            pass


    def update_health(self):
        self._reset_bandwidth_at_midnight_if_needed()
        is_win = platform.system().lower() == "windows"
        is_mac_os = platform.system().lower() == "darwin"
        param = "-n" if is_win else "-c"
        timeout_flag = "-w" if is_win else "-W"


        # Packet sizes for the packet-pair bandwidth probe below: a tiny
        # packet and a near-MTU one. Both are used ONLY as the payload_bytes
        # difference in the math — never assumed to equal actual throughput
        # on their own.
        _SMALL_PROBE_BYTES = 32
        _LARGE_PROBE_BYTES = 1400

        # Packet-pair math derives speed from a delta measured in
        # milliseconds, so once that delta drops below roughly the timing
        # resolution/noise floor of the probe itself, the "speed" it implies
        # isn't measuring the link anymore — it's measuring noise (e.g. one
        # lucky ~0.07ms delta reads as ~300 Mbps out of nowhere on a link
        # that's actually struggling). Discarding any single pair/burst whose
        # implied speed is above this ceiling — generous, well above typical
        # consumer Wi-Fi/LAN throughput — keeps those spikes out of the
        # estimate instead of letting one noisy pair drag or dominate the
        # median.
        _MAX_PLAUSIBLE_MBPS = 1200.0

        # How many speed-probe attempts a reading stays valid for. A number
        # older than this is no longer shown as if it were current: with no
        # fresh, usable sample for this many probes in a row, the honest
        # display is "--", not a value frozen from the last time a probe
        # happened to work (which is what made the column look stuck).
        _SPEED_STALE_PROBES = 8

        def _estimate_speed_mbps(small_rtts_ms, large_rtts_ms):
            """
            Packet-pair dispersion: bandwidth from the RTT *difference*
            between a small and a large probe, not from either RTT alone.

            A single RTT is mostly fixed propagation/processing delay —
            that delay is there no matter how fast the link is, which is
            why the old approach (total transfer bits / one RTT) collapsed
            to a near-zero "speed" the instant RTT went above ~1ms, even on
            a fast, healthy link. The fixed delay is still baked into every
            RTT here too, but it cancels out when we subtract: the *extra*
            time the large packet took over the small one is (mostly) just
            the extra bytes being serialized onto the wire, which is what
            actually depends on link bandwidth.

            Used for the OS-ping fallback path, where the small burst and
            large burst are two separate subprocess calls run one after
            the other rather than interleaved — see
            _estimate_speed_mbps_paired for the more accurate version used
            when Scapy is available.
            """
            if not small_rtts_ms or not large_rtts_ms:
                return None
            small_rtt_s = min(small_rtts_ms) / 1000.0
            large_rtt_s = min(large_rtts_ms) / 1000.0
            delta_s = large_rtt_s - small_rtt_s
            if delta_s <= 0:
                # Link is fast enough (or samples too noisy) that the size
                # difference didn't move the needle — we can't derive a
                # number from this pair, not "speed is infinite".
                return None
            # Both packets round-trip (out and back), so double the size
            # delta before converting to bits.
            delta_bits = (_LARGE_PROBE_BYTES - _SMALL_PROBE_BYTES) * 2 * 8
            mbps = delta_bits / (delta_s * 1_000_000)
            if mbps > _MAX_PLAUSIBLE_MBPS:
                # Implausibly high for a two-packet OS-ping delta — almost
                # certainly sub-millisecond timer noise, not real capacity.
                # Treat it the same as "couldn't derive a number" rather
                # than reporting a number nobody should trust.
                return None
            return round(mbps, 1)

        def _estimate_speed_mbps_paired(rtt_pairs):
            """
            More accurate variant of _estimate_speed_mbps for when the
            small and large probes were sent as genuine back-to-back
            PAIRS (see _scapy_paired_probe) rather than as two separate
            bursts fired several probes apart.

            The old approach took the single best (minimum) RTT out of
            an entire small-probe burst and the single best RTT out of an
            entire large-probe burst, then diffed those two. That silently
            assumes both bursts saw the same network conditions — true on
            a quiet link, but on anything noisier (WiFi especially) the
            three small probes and three large probes can each land in a
            different momentary condition, so comparing their two
            "bests" can produce a delta that doesn't correspond to any
            single real moment on the link.

            Here, each small/large probe in a pair was sent moments apart
            (see _scapy_paired_probe's inter-probe gap), so both members
            of a pair experienced essentially the same conditions. A
            per-pair delta is computed for every pair, and the MEDIAN of
            those deltas is used — not the best, not the average — so a
            single unlucky/lucky pair can't dominate the estimate the way
            a single lucky "min" reading could before, while still not
            being pulled off-center by one outlier pair the way a plain
            mean would be.
            """
            candidate_mbps = []
            for small_rtt_ms, large_rtt_ms in rtt_pairs:
                if small_rtt_ms is None or large_rtt_ms is None:
                    continue
                delta_s = (large_rtt_ms - small_rtt_ms) / 1000.0
                if delta_s <= 0:
                    continue
                delta_bits = (_LARGE_PROBE_BYTES - _SMALL_PROBE_BYTES) * 2 * 8
                pair_mbps = delta_bits / (delta_s * 1_000_000)
                if pair_mbps > _MAX_PLAUSIBLE_MBPS:
                    # This one pair's delta is small enough to be noise
                    # rather than a real reading — drop it so it can't pull
                    # (or, with few pairs, outright become) the median.
                    continue
                candidate_mbps.append(pair_mbps)
            if not candidate_mbps:
                return None
            return round(statistics.median(candidate_mbps), 1)

        def _scapy_paired_probe(ip, pairs=3, timeout=0.3, inter_probe_gap=0.02):
            """
            Sends `pairs` small/large ICMP probes interleaved
            (small, large, small, large, ...) instead of as two separate
            back-to-back bursts, so each pair reflects one moment on the
            link rather than the small burst and large burst potentially
            landing in two different network conditions. Returns a list
            of (small_rtt_ms, large_rtt_ms) tuples — a pair is only
            included if BOTH probes in it got a reply, since a pair with
            one missing side can't produce a delta at all.
            """
            if not _SCAPY_AVAILABLE:
                return []
            rtt_pairs = []
            dropped_large_in_a_row = 0
            for _ in range(pairs):
                _, small_rtts = _scapy_icmp_ping(
                    ip, count=1, timeout=timeout, payload_bytes=_SMALL_PROBE_BYTES,
                    inter_packet_delay=0.0
                )
                if inter_probe_gap > 0:
                    time.sleep(inter_probe_gap)
                _, large_rtts = _scapy_icmp_ping(
                    ip, count=1, timeout=timeout, payload_bytes=_LARGE_PROBE_BYTES,
                    inter_packet_delay=0.0
                )
                if small_rtts and large_rtts:
                    rtt_pairs.append((small_rtts[0], large_rtts[0]))
                    dropped_large_in_a_row = 0
                elif small_rtts and not large_rtts:
                    # Device answers small pings but the big one got no
                    # reply (firewall/phone dropping larger ICMP). Each
                    # such miss burns a full `timeout` of waiting, and
                    # this now runs every cycle — after two in a row,
                    # stop instead of spending the rest of the pairs on
                    # the same wait.
                    dropped_large_in_a_row += 1
                    if dropped_large_in_a_row >= 2:
                        break
                if inter_probe_gap > 0:
                    time.sleep(inter_probe_gap)
            return rtt_pairs


        def _arp_still_present(ip):
            # Ground truth first: an active Scapy probe puts a real ARP
            # request on the wire and waits for a reply, so there's no
            # cache in the loop at all — no permission dance needed to
            # clear a stale entry, no "incomplete" row left over from a
            # device that just disconnected. If Scapy is installed and
            # able to send raw packets here, this settles Idle vs Offline
            # directly and we're done.
            status, mac = _scapy_arp_resolve(ip, timeout=0.8)
            if status == "ok":
                return mac is not None


            if status == "no_permission" and not getattr(self, "_scapy_permission_warned", False):
                self._scapy_permission_warned = True
                ts = datetime.now().strftime("%H:%M:%S")
                self.add_troubleshoot_log(
                    f"[{ts}] NOTE: Scapy is installed but can't send raw ARP probes without "
                    f"admin/root privileges (and Npcap on Windows) — falling back to the OS's "
                    f"ARP table for Idle vs Offline detection."
                )


            # Scapy is either not installed or not usable here — fall back
            # to reading the OS's own ARP table below.
            #
            # ARP replies are typically handled by the network adapter
            # itself, below the OS's application-level sleep state — a
            # device that's deep asleep and ignoring ICMP will usually
            # still answer ARP, so a live entry is a strong sign it's
            # still on the network, not actually gone.
            #
            # Rather than trusting whatever's already sitting in the OS's
            # ARP cache (which can occasionally outlive a device that's
            # truly disconnected — a stale-cache false positive), this
            # forces a FRESH read every time: delete any existing entry
            # for this IP, send one quick probe to trigger a brand new
            # resolution attempt, then check the table again. If the
            # device is really there, it re-populates almost instantly;
            # if it's actually gone, the entry simply won't come back.
            try:
                _enc = "cp1252" if is_win else "utf-8"


                delete_ok = False
                try:
                    if is_win or is_mac_os:
                        del_result = _run(["arp", "-d", ip], capture_output=True, text=True,
                                           encoding=_enc, errors="replace")
                    else:
                        del_result = _run(["ip", "neigh", "del", ip], capture_output=True, text=True,
                                           encoding=_enc, errors="replace")
                    delete_ok = (del_result.returncode == 0)
                except Exception:
                    delete_ok = False


                if not delete_ok and not getattr(self, "_arp_delete_permission_warned", False):
                    # This silently failed before — _run() doesn't raise on
                    # a non-zero exit code, only on things like a missing
                    # binary, so a permission-denied delete (the normal
                    # case without admin/root — all three OSes require
                    # elevated privileges to clear another host's ARP
                    # entry) was going completely unnoticed. Without this,
                    # a device you just disconnected can keep reading as
                    # "Idle" off its old, now-stale cache entry, since we
                    # never actually cleared it to force a fresh check.
                    self._arp_delete_permission_warned = True
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.add_troubleshoot_log(
                        f"[{ts}] NOTE: Can't clear ARP cache entries without admin/root privileges "
                        f"— Idle vs Offline detection is reading the OS's existing ARP cache as-is, "
                        f"which can briefly lag behind a device that was JUST disconnected. Run this "
                        f"app with elevated privileges for instantly-accurate detection instead."
                    )


                _run(["ping", param, "1", timeout_flag, "500", ip],
                     capture_output=True, text=True, encoding=_enc, errors="replace",
                     timeout=3)


                # -n (numeric) is critical here, not just an optimization:
                # without it, arp -a does a reverse-DNS lookup for every
                # cached entry before it can print anything. If DNS is slow
                # or unreachable — which is common precisely when the
                # network is degraded, i.e. exactly when a device is going
                # offline — that lookup can hang for a long time. And since
                # this whole function runs INSIDE self.lock (see check_device
                # above), a hang here doesn't just delay one device's status:
                # every other place that needs self.lock — including the
                # UI's own refresh_panel on the main thread — blocks right
                # along with it, freezing the entire app until force-quit.
                # -n skips DNS entirely (numeric IPs only), and the explicit
                # timeout is a second line of defense in case the command
                # itself still hangs for some other reason.
                arp_cmd = ["arp", "-a"] if is_win else ["arp", "-an"]
                arp_out = _run(arp_cmd, capture_output=True, text=True,
                                encoding=_enc, errors="replace", timeout=3).stdout


                # A disconnected device's ARP entry often doesn't vanish
                # immediately — it can linger as an UNRESOLVED entry (e.g.
                # "? (192.168.1.42) at <incomplete> on en0" on Linux/macOS,
                # or a stale row on Windows). That line still contains the
                # IP string, so a plain substring match wrongly treats it
                # as "device still present". Require an actual resolved
                # MAC address on the matching line instead.
                mac_pattern = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
                for line in arp_out.splitlines():
                    if ip not in line:
                        continue
                    if "incomplete" in line.lower() or "failed" in line.lower():
                        continue
                    if mac_pattern.search(line):
                        return True
                return False
            except Exception:
                return False


        def check_device(device):
            # 10 measured pings, plus one warm-up ping when Scapy is
            # available. More samples reduce the coarse packet-loss steps
            # (10% per packet instead of 16.7%) and make the latency/jitter
            # statistics less sensitive to one transient packet. The warm-up
            # keeps initial ARP/neighbor resolution out of the measured RTT.
            # The health loop remains bounded by the shared worker pool.
            #
            # More samples means a steadier
            # average and a trimmed mean that has more room to actually
            # smooth things out. The health loop runs every 2s, and with
            # self-timed Scapy probes (below) each packet only costs its
            # real RTT plus a capped per-packet timeout, not a slow OS
            # ping subprocess spin-up, so the extra samples don't meaningfully
            # eat into that budget.
            SAMPLE_COUNT = 10
            is_win = platform.system().lower() == "windows"

            # Ground truth first: send ICMP echoes ourselves and time each
            # round trip with a high-resolution clock. This sidesteps two
            # real accuracy problems with parsing the OS ping tool's own
            # "time=Xms" text — Windows rounds that to whole milliseconds
            # (no decimals at all), and every platform's ping binary uses
            # its own timer with its own precision, not one we control.
            # Falls back to the OS ping tool below only when Scapy isn't
            # installed or can't send raw packets here (needs root/admin,
            # plus Npcap on Windows).
            def _os_ping_rtts(target_ip, size_bytes, ping_count=3, wait_ms=400):
                """Run the OS ping tool with an explicit payload size and
                parse per-packet RTTs from its text output. Used only by
                the bandwidth packet-pair probe further down — separate
                from (and doesn't affect) the main latency/jitter/loss
                sampling above/below, which stays on the default ping."""
                size_flag = "-l" if is_win else "-s"
                try:
                    r = _run(
                        ["ping", param, str(ping_count), timeout_flag, str(wait_ms),
                         size_flag, str(size_bytes), target_ip],
                        capture_output=True, text=True,
                        encoding="cp1252" if is_win else "utf-8", errors="replace"
                    )
                except Exception:
                    return []
                out = r.stdout + r.stderr
                found = [float(m) for m in re.findall(r"time[=<]\s*([\d\.]+)", out)]
                for _ in re.finditer(r"time<1ms", out):
                    found.append(0.5)
                return found

            scapy_status, scapy_latencies = _scapy_icmp_ping(
                device.ip, count=SAMPLE_COUNT, timeout=0.3, warmup=True
            )

            ping_out = ""
            if scapy_status == "ok":
                latencies = scapy_latencies
                alive = len(latencies) > 0
                loss_pct = round(100 * (SAMPLE_COUNT - len(latencies)) / SAMPLE_COUNT)
            else:
                if scapy_status == "no_permission" and not getattr(self, "_scapy_icmp_permission_warned", False):
                    self._scapy_icmp_permission_warned = True
                    ts = datetime.now().strftime("%H:%M:%S")
                    self.add_troubleshoot_log(
                        f"[{ts}] NOTE: Scapy is installed but can't send raw ICMP probes without "
                        f"admin/root privileges (and Npcap on Windows) — falling back to the OS's "
                        f"ping tool for latency, which is less precise (Windows rounds to whole ms)."
                    )

                # Kept at the default small packet size — some routers/firewalls
                # silently drop larger ICMP payloads, which was making devices
                # look offline. The speed estimate below instead assumes a
                # realistic transfer size mathematically, without needing to
                # actually risk sending a bigger packet.
                result = _run(
                    ["ping", param, str(SAMPLE_COUNT), timeout_flag, "400", device.ip],
                    capture_output=True,
                    text=True,
                    encoding="cp1252" if is_win else "utf-8",
                    errors="replace"
                )
                ping_out = result.stdout + result.stderr
                # Exit code alone isn't reliable: on Windows, ping can exit
                # 0 when the only "reply" is the local machine saying
                # "Destination host unreachable" — no real reply from the
                # target at all. A genuine echo reply always carries a TTL
                # field ("TTL=64" / "ttl=64", left untranslated on
                # non-English Windows too, unlike "time="), so require it.
                alive = result.returncode == 0 and re.search(r"ttl[=:]", ping_out, re.IGNORECASE) is not None

                # Latency — parsed from the OS ping tool's own text output.
                latencies = _parse_ping_times(ping_out)

                # Packet loss — parse summary line (macOS/Linux/Windows all print this)
                loss_m = re.search(r"([\d\.]+)%\s*(?:packet\s*)?loss", ping_out, re.IGNORECASE)
                if loss_m:
                    loss_pct = round(float(loss_m.group(1)))
                elif not alive:
                    loss_pct = 100
                else:
                    loss_pct = 0
                # An "unreachable" run can still print a summary line
                # claiming 0% loss — if nothing really answered, it's 100%.
                if not alive:
                    loss_pct = 100


            # TCP fallback if ping fails — this proves the device is still
            # present on the network even though ICMP isn't getting through,
            # but it should NOT be treated the same as a real ping reply.
            # A device that only answers on a background TCP port (SMB,
            # a printer's web UI, SSH left enabled, etc.) while it's
            # asleep/idle isn't "actively responding" the way a live ping
            # is — forcing alive=True here was making such devices show
            # Online forever and skip Idle detection entirely, since only
            # the "not alive" branches below ever check for Idle. Track it
            # separately instead so it can route straight to Idle.
            icmp_alive = alive
            tcp_reachable = False
            if not alive:
                for port in [80, 443, 22, 8080, 445]:
                    try:
                        with socket.create_connection((device.ip, port), timeout=0.3):
                            tcp_reachable = True
                            break
                    except Exception:
                        pass


            # TCP-connect latency — a secondary reading alongside ICMP, not
            # a replacement for it. ICMP and TCP travel different paths
            # through some routers/firewalls (ICMP is sometimes deprioritized
            # or handled in software while TCP isn't, or vice versa), so a
            # single connect timing gives a second, independently-measured
            # data point for cross-checking the ICMP figure — useful in the
            # detail/diagnostic views even though the main latency stat
            # below stays ICMP-based for consistency with packet loss/jitter.
            #
            # Throttled to every 3rd cycle, same treatment as the bandwidth
            # probe below: most devices don't have any of these 5 ports
            # open, so on a large network this loop was burning up to
            # ~1.5s per device EVERY 2s cycle just to fail 5 times in a
            # row — a big share of the per-device work that piled up the
            # health-check backlog as device count grew. In between real
            # probes we just keep showing the last measured value instead
            # of re-running the full 5-port sweep every single cycle.
            tcp_latency_ms = getattr(device, "_tcp_latency_ms", None)
            tcp_cycle = getattr(device, "_tcp_lat_probe_cycle", 0)
            device._tcp_lat_probe_cycle = tcp_cycle + 1
            if tcp_cycle % 3 == 0:
                tcp_latency_ms = None
                for port in [80, 443, 22, 8080, 445]:
                    try:
                        t0 = time.perf_counter()
                        with socket.create_connection((device.ip, port), timeout=0.3):
                            tcp_latency_ms = (time.perf_counter() - t0) * 1000.0
                        break
                    except Exception:
                        pass
                device._tcp_latency_ms = tcp_latency_ms


            # Latency — median, not a mean-with-one-sample-trimmed: with only
            # a handful of packets/cycle, a mean is still pulled around even
            # after dropping the single highest sample — one lucky fast reply
            # skews it low, and more than one delayed packet (a retry storm,
            # not just one) still drags it high. The median is the standard
            # robust choice real ping/monitoring tools (mtr, smokeping) use
            # for exactly this reason: it reflects the device's typical round
            # trip regardless of how many samples on either side went
            # sideways, with no sample-count-dependent special case needed.
            # Jitter below still uses the full, untrimmed sample set —
            # that's specifically about capturing that variance, not
            # smoothing over it.
            avg_latency = statistics.median(latencies) if latencies else 0


            # Jitter — mean ABSOLUTE DIFFERENCE between consecutive samples,
            # not population stdev. Stdev measures spread around the mean,
            # which reacts quadratically to a single outlier: one delayed
            # packet in a burst of 6 inflates stdev far more than it actually
            # inflates the packet-to-packet wobble a person means by
            # "jitter". This mirrors RFC 3550's jitter definition (built from
            # successive differences, not variance around a mean) and stays
            # linear in the deviation, so one bad sample nudges the number
            # instead of dominating it.
            if len(latencies) > 1:
                diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
                jitter = round(sum(diffs) / len(diffs), 1)
            else:
                jitter = 0.0


            # Speed — packet-pair dispersion: send a small probe and a
            # near-MTU probe, then derive bandwidth from the RTT
            # *difference* between them (see _estimate_speed_mbps for why
            # a single RTT can't do this). A device that's dropped larger
            # ICMP payloads just yields no large-probe samples, which
            # reports "--" rather than a wrong number — it never affects
            # the alive/online determination above.
            #
            # speed_fresh is True only on a cycle that genuinely took a new
            # measurement. The smoothing history further down uses it so a
            # reused (stale) reading is never counted as a new sample.
            speed_fresh = False
            if alive:
                if scapy_status == "ok":
                    # Interleaved small/large pairs (see
                    # _scapy_paired_probe) rather than two separate bursts
                    # — each pair reflects one moment on the link, and the
                    # median of several pairs' deltas (see
                    # _estimate_speed_mbps_paired) is far less swayed by a
                    # single noisy probe than the old "best-of-burst vs
                    # best-of-burst" comparison was. The short pause
                    # before starting still keeps this probe from running
                    # back-to-back with the latency burst just above.
                    time.sleep(0.05)
                    # 3 pairs EVERY cycle (6 ICMP sends), rather than 7 pairs
                    # every 3rd cycle (~4.7 sends/cycle on average). About
                    # the same load per device, but a genuinely new
                    # measurement lands on every 2s cycle instead of one
                    # every ~6s with stale reuse in between. The median
                    # over the last several cycles (see the smoothing
                    # history in "Write live stats") covers for the
                    # occasional cycle where the plausibility filter drops
                    # most of a small set of pairs.
                    size_rtts = _scapy_multisize_probe(device.ip, rounds=2, timeout=0.3)
                    device._speed_mbps = _update_speed_windows(device, size_rtts)
                    speed_fresh = True
                    if device._speed_mbps is None:
                        device._speed_note = (
                            "large probe got no reply (device/firewall drops big ICMP)"
                            if not size_rtts[_SPEED_PROBE_SIZES[-1]] else
                            "still gathering samples / size-vs-RTT slope too flat to measure"
                        )
                    else:
                        device._speed_note = None
                else:
                    # OS-ping fallback: 2 extra subprocess spawns per
                    # device just for this probe, on top of the main
                    # latency ping and the TCP checks above. This used to
                    # only actually probe every 3rd cycle per device (the
                    # other cycles reused the last measured speed), which
                    # kept subprocess load down on larger networks but
                    # left the speed column visibly lagging two cycles
                    # out of three behind latency/jitter, which update
                    # every cycle. Now probed EVERY cycle instead, same
                    # cadence as the scapy path above, so speed stays in
                    # step with the rest of the dashboard. Worth watching
                    # if this reintroduces the lag/crashes the skip was
                    # originally added to avoid on dozens/hundreds of
                    # devices.
                    small_bw_rtts = _os_ping_rtts(device.ip, _SMALL_PROBE_BYTES)
                    large_bw_rtts = _os_ping_rtts(device.ip, _LARGE_PROBE_BYTES)
                    device._speed_mbps = _update_speed_windows(
                        device,
                        {_SMALL_PROBE_BYTES: small_bw_rtts, _LARGE_PROBE_BYTES: large_bw_rtts},
                    )
                    speed_fresh = True
                    if device._speed_mbps is None:
                        device._speed_note = (
                            "large probe got no reply (device/firewall drops big ICMP)"
                            if not large_bw_rtts else
                            "OS ping timing too coarse (whole ms) to measure a delta"
                        )
                    else:
                        device._speed_note = None
            else:
                device._speed_mbps = None
                device._speed_rtt_windows = None


            # Write live stats
            with self.lock:
                # Displayed latency/jitter: short rolling median over the
                # last few cycles, same treatment already used for packet
                # loss below. A power-save/idle device's raw per-cycle
                # reading can swing a lot even though nothing about the
                # device actually changed (depends on where in its wake
                # cycle a probe happens to land — see the earlier
                # explanation), so smoothing what's DISPLAYED keeps the
                # table from looking like it's constantly jumping around.
                # Status detection elsewhere (avg_lat_hist, baseline
                # tracking, etc.) keeps its own separate raw-based history
                # untouched — this only changes what's shown in this column.
                lat_disp_hist = getattr(device, "_latency_display_history", None)
                if lat_disp_hist is None:
                    lat_disp_hist = deque(maxlen=5)
                    device._latency_display_history = lat_disp_hist
                jit_disp_hist = getattr(device, "_jitter_display_history", None)
                if jit_disp_hist is None:
                    jit_disp_hist = deque(maxlen=5)
                    device._jitter_display_history = jit_disp_hist

                if latencies and alive:
                    lat_disp_hist.append(avg_latency)
                    jit_disp_hist.append(jitter)
                    device.latency = f"{round(statistics.median(lat_disp_hist))}ms"
                    device.jitter  = f"{round(statistics.median(jit_disp_hist))}ms"
                else:
                    # No usable reading this cycle — clear the window
                    # instead of holding onto a stale smoothed figure, so
                    # a genuine gap shows as "--" and the device doesn't
                    # resume with old, pre-gap readings still blended in.
                    lat_disp_hist.clear()
                    jit_disp_hist.clear()
                    device.latency = "--"
                    device.jitter  = "--"
                # Packet loss shown on the dashboard: a short rolling median
                # of the last few cycles rather than this single cycle's raw
                # figure alone. With only SAMPLE_COUNT pings per cycle, loss
                # can only land on coarse steps (0%, 10%, 20%, ...), so one
                # random dropped packet reads as a much bigger spike than it
                # really is. Status detection below (is_unstable, fail_count
                # escalation) intentionally keeps using THIS cycle's raw
                # loss_pct, unsmoothed — a real problem still has to be
                # caught immediately, not averaged away — this only steadies
                # what the person actually sees in the table.
                loss_hist = getattr(device, "_loss_pct_history", None)
                if loss_hist is None:
                    loss_hist = deque(maxlen=5)
                    device._loss_pct_history = loss_hist
                loss_hist.append(loss_pct)
                device.packet_loss    = f"{round(statistics.median(loss_hist))}%"
                device.tcp_latency    = f"{tcp_latency_ms:.2f}ms" if tcp_latency_ms is not None else "--"
                spd = getattr(device, "_speed_mbps", None)
                if speed_fresh:
                    device._speed_probe_no = getattr(device, "_speed_probe_no", 0) + 1
                probe_no = getattr(device, "_speed_probe_no", 0)
                if spd and spd > 0 and speed_fresh:
                    # A single cycle's packet-pair estimate is drawn from
                    # just 3 small + 3 large probes, so on a jittery link
                    # one unlucky/lucky RTT can send the raw number
                    # swinging wildly cycle to cycle (e.g. 106 Mbps one
                    # reading, 0.1 Mbps the next, with nothing about the
                    # actual link changing that fast). Smoothing over the
                    # last few valid readings with a median — rather than
                    # showing each raw estimate as-is — filters out that
                    # single-cycle noise while still tracking a real,
                    # sustained change in the link within a few cycles.
                    hist = getattr(device, "_speed_estimate_history", None)
                    if hist is None:
                        # 8 cycles instead of 5: now that implausible
                        # single-pair spikes are filtered out before this
                        # point, the remaining noise is smaller-magnitude —
                        # a slightly longer window trades a little more lag
                        # on a genuine speed change for a steadier number
                        # the rest of the time.
                        hist = deque(maxlen=8)
                        device._speed_estimate_history = hist
                    # Entries carry the probe number they were taken at, so
                    # readings older than _SPEED_STALE_PROBES drop out of
                    # the median instead of lingering just because there
                    # haven't been 8 newer ones yet.
                    hist.append((probe_no, spd))
                    recent = [v for n, v in hist if probe_no - n < _SPEED_STALE_PROBES]
                    smoothed_spd = statistics.median(recent)
                    device._last_good_speed_mbps = smoothed_spd
                    device._last_good_speed_probe_no = probe_no
                    display_speed = round(smoothed_spd * 2) if 6 <= smoothed_spd <= 15 else round(smoothed_spd) if smoothed_spd > 15 else 0
                    if display_speed >= 10:
                        device.network_speed = f"{display_speed:,} Mbps"
                        # Remember what was last SHOWN, so a later cycle with
                        # no new output keeps displaying it instead of "--".
                        device._last_shown_speed = device.network_speed
                    else:
                        # Below the display threshold: not a displayable new
                        # output, so keep showing the previous value.
                        device.network_speed = getattr(device, "_last_shown_speed", "--")
                elif alive:
                    # This cycle had no fresh usable estimate (no
                    # large-probe samples, a non-positive RTT delta, or an
                    # OS-ping cycle that skipped probing). Even though the
                    # device IS responding, showing the last successful
                    # (smoothed) reading here made it look like a live,
                    # current measurement when it wasn't one this cycle —
                    # "--" honestly reflects that there's no current
                    # reading, the same way the "device didn't respond"
                    # branch below already behaves.
                    # (_last_good_speed_mbps itself is left untouched — the
                    # consumption estimate below still uses it; only the
                    # DISPLAY no longer presents an old reading as current.)
                    #
                    # UPDATE: the last displayed value is now held until a new
                    # reading arrives, rather than dropping to "--" (the dash
                    # is only shown if this device never had a reading yet).
                    device.network_speed = getattr(device, "_last_shown_speed", "--")
                else:
                    # Device didn't respond at all this cycle (the path
                    # that leads to Idle/Unstable/Offline below) — showing
                    # a speed reading from before it stopped responding is
                    # misleading (looks like it's still measuring a live
                    # connection). "--" honestly reflects that there's no
                    # current reading, regardless of what was last cached.
                    #
                    # UPDATE: same hold-last-value behavior as above — the
                    # last displayed speed stays until a new reading replaces
                    # it ("--" only if there has never been one).
                    device.network_speed = getattr(device, "_last_shown_speed", "--")
                device.last_check     = datetime.now().strftime("%H:%M:%S")

                # Estimated data consumption: since a normal client machine
                # can't see another device's actual traffic on a switched
                # network (that needs router-side SNMP, which this app
                # doesn't have), this approximates it by treating the
                # per-cycle speed reading above as that device's rate for
                # the real wall-clock time since its last check, and
                # integrating that over time. It's a genuine estimate, not
                # a metered byte count — see get_bandwidth_snapshot, which
                # is careful to always label it that way to the user.
                now_ts = time.time()
                last_ts = getattr(device, "_bw_last_ts", None)
                # Uses the same smoothed figure as the displayed Network
                # Speed (device._last_good_speed_mbps, updated above) so
                # the consumption estimate isn't driven by the same
                # single-cycle noise that used to make the raw `spd`
                # swing wildly between cycles.
                rate_mbps = getattr(device, "_last_good_speed_mbps", None)

                # Rolling per-interval history for the bandwidth popup's
                # graph (see engine.get_device_bandwidth_history): how many
                # bytes were estimated to have been used in THIS cycle, not
                # the running cumulative total — a graph of the cumulative
                # total would just be an always-climbing line, whereas
                # per-interval usage actually shows when a device was
                # busier or quieter. Capped at the last 60 samples (~2
                # minutes at this loop's 2s cadence) so it stays a small,
                # fixed amount of memory per device regardless of session
                # length.
                hist = getattr(device, "_bw_rate_history", None)
                if hist is None:
                    hist = deque(maxlen=60)
                    device._bw_rate_history = hist

                if last_ts is not None and alive and rate_mbps:
                    elapsed = max(0.0, now_ts - last_ts)
                    delta_bytes = (
                        (rate_mbps * 1_000_000 / 8) * elapsed * _ASSUMED_UTILIZATION_FACTOR
                    )
                    device._bw_estimated_bytes = (
                        getattr(device, "_bw_estimated_bytes", 0.0) + delta_bytes
                    )
                    # Same delta, same moment, into the network-wide
                    # running total — see its field comment in __init__
                    # for why this has to be its own counter rather than
                    # a live sum of every device's current total.
                    self._bw_network_estimated_bytes += delta_bytes
                    hist.append((now_ts, delta_bytes))
                elif last_ts is not None and alive:
                    # Device IS responding, but this cycle produced no
                    # usable speed reading (packet-pair delta was <= 0, or
                    # the large probe got no replies at all — e.g. a
                    # firewall dropping bigger ICMP payloads) AND no prior
                    # reading exists yet to fall back on. This is not the
                    # same thing as "confirmed zero usage" — it's "unknown"
                    # — so it's recorded as None rather than 0.0. The graph
                    # (see get_device_bandwidth_history) drops these points
                    # entirely instead of drawing a false flat baseline,
                    # and the popup tells the user why if EVERY sample
                    # turns out to be one of these.
                    hist.append((now_ts, None))
                elif last_ts is not None:
                    # Device is unreachable this cycle (network_speed shows
                    # "--"). This genuinely is zero usage — nothing could
                    # have been transferred while it wasn't responding —
                    # so unlike the case above, 0.0 is the correct, known
                    # value here, not a stand-in for "no reading".
                    hist.append((now_ts, 0.0))
                device._bw_last_ts = now_ts


            # Rolling history: (alive, latency, loss_pct)
            if not hasattr(device, "ping_history"):
                device.ping_history = []
            device.ping_history.append((alive, avg_latency, jitter, loss_pct))
            if len(device.ping_history) > 3:
                device.ping_history.pop(0)


            history = device.ping_history
            all_dead      = all(not r[0] for r in history) and len(history) >= 3
            any_alive     = any(r[0] for r in history)
            if device.status == "Idle":
                # Recovering FROM Idle needs to react to what the device is
                # doing RIGHT NOW. Averaging in the last couple of history
                # entries (still holding the very idle-era, high-latency
                # readings that put the device in Idle to begin with) keeps
                # the average artificially high for another cycle or two
                # even after the device is genuinely back in active use —
                # so someone who picks their device back up only sees the
                # dashboard catch up several seconds later, or not at all if
                # they were only briefly active. Use this cycle's own raw
                # reading instead so a real drop in latency is seen the
                # moment it happens. The recovery branch below acts on the
                # first clean cycle (no multi-cycle debounce).
                avg_lat_hist = avg_latency if alive else 0
                avg_jit_hist = jitter if alive else 0
            else:
                avg_lat_hist = sum(r[1] for r in history if r[0]) / max(1, sum(1 for r in history if r[0]))
                avg_jit_hist = sum(r[2] for r in history if r[0]) / max(1, sum(1 for r in history if r[0]))

            # Per-device baseline: what this specific device's latency
            # normally looks like when it's clearly fine (clean, under the
            # fixed 150ms bar). Some devices' power-save behavior only
            # slows them down modestly relative to their own normal speed
            # (e.g. 70ms baseline creeping to 125ms while idle) without ever
            # crossing 150ms outright — for those, 150ms alone never
            # notices anything changed. Only cycles that were themselves
            # clean and fast go into this history, so an idle stretch can't
            # drag the device's own "normal" down and end up masking itself.
            if alive and loss_pct == 0 and avg_latency < 150:
                base_hist = getattr(device, "_baseline_latency_history", None)
                if base_hist is None:
                    base_hist = deque(maxlen=20)
                    device._baseline_latency_history = base_hist
                base_hist.append(avg_latency)
            base_hist = getattr(device, "_baseline_latency_history", None)
            # Require a handful of samples before trusting a baseline at
            # all — one or two early readings shouldn't get to decide what
            # "normal" means for this device.
            baseline_latency = statistics.median(base_hist) if base_hist and len(base_hist) >= 5 else None

            # High-latency test: the fixed 150ms bar still applies on its
            # own (works even before a baseline exists, and catches a
            # device that's just objectively slow). Alongside it, a clear
            # jump above THIS device's own established baseline also
            # counts — at least 1.5x AND at least +30ms, so a device with a
            # naturally tiny baseline (a few ms) doesn't get flagged from
            # ordinary noise alone doubling it. Expressed as a single
            # number (whichever bar is lower) so hysteresis below can be
            # applied to it in one place.
            high_latency_line = 150 if baseline_latency is None else min(
                150, max(baseline_latency * 1.5, baseline_latency + 30)
            )

            # Hysteresis: without this, a device whose latency sits right on
            # the line flips status every single cycle from a few ms of
            # ordinary noise nudging it across — nothing about the device
            # actually changed, only which side of one exact number this
            # cycle's reading landed on. Once already flagged slow
            # (Idle/Unstable), it has to drop a bit further BELOW the line
            # to be called fast again, rather than just barely ducking under
            # it; once already Online, it has to clear a bit further ABOVE
            # the line to be called slow. That gap (15%, floor of 15ms) is
            # the dead zone a reading has to fully cross before the status
            # actually changes, instead of chattering back and forth right
            # on the boundary.
            was_already_slow = device.status in ("Idle", "Unstable", "Offline")
            hysteresis_margin = max(15.0, high_latency_line * 0.15)
            effective_line = (high_latency_line - hysteresis_margin) if was_already_slow else high_latency_line
            is_high_latency = avg_lat_hist > effective_line

            # Per-device jitter baseline: same idea as the latency baseline
            # above, and for the same reason — some devices are just
            # naturally "chattier" than others in normal, healthy use (a
            # weaker-signal device a bit further from the AP will show more
            # packet-to-packet wobble than one sitting right next to it,
            # with nothing actually wrong). A fixed jitter bar can't tell
            # "this is just how this device normally looks" apart from "this
            # device just got flaky", so — same as latency — only cycles
            # that were themselves clean and fast feed the baseline, and
            # what counts as "high" is judged against THIS device's own
            # established normal, not a single number applied to everyone.
            if alive and loss_pct == 0 and avg_latency < 150:
                jit_base_hist = getattr(device, "_baseline_jitter_history", None)
                if jit_base_hist is None:
                    jit_base_hist = deque(maxlen=20)
                    device._baseline_jitter_history = jit_base_hist
                jit_base_hist.append(jitter)
            jit_base_hist = getattr(device, "_baseline_jitter_history", None)
            baseline_jitter = statistics.median(jit_base_hist) if jit_base_hist and len(jit_base_hist) >= 5 else None

            # High-jitter test: fixed 60ms bar on its own (works before a
            # baseline exists, and still catches a device that's just
            # objectively erratic), OR a clear jump above THIS device's own
            # baseline — at least 2.5x AND at least +40ms, wider margins
            # than latency's since jitter is naturally noisier sample to
            # sample. Same "whichever bar is lower" shape as latency so the
            # same hysteresis treatment applies cleanly.
            high_jitter_line = 60 if baseline_jitter is None else min(
                60, max(baseline_jitter * 2.5, baseline_jitter + 40)
            )
            hysteresis_margin_jit = max(10.0, high_jitter_line * 0.15)
            effective_jitter_line = (high_jitter_line - hysteresis_margin_jit) if was_already_slow else high_jitter_line
            # Uses the rolling (up to 3-cycle) average, same as latency —
            # a single noisy burst can't flip this on its own, only a
            # sustained jump above the device's own normal can.
            is_high_jitter = avg_jit_hist > effective_jitter_line

            # Unstable if: current ping failed OR latency high (fixed bar or
            # relative to this device's own baseline) OR jitter high (same,
            # relative to this device's own baseline) OR this cycle has
            # packet loss. The jitter check exists specifically for the
            # case latency and loss alone miss: 0% loss, latency that never
            # crosses its own bar, but the device is bouncing around far
            # more than IT normally does — a real sign of a flaky link that
            # was previously invisible here.
            # Windows OS ping reports latency at whole-millisecond precision
            # and can produce timing values that differ from the Scapy path.
            # For Windows, a successful ICMP reply with no packet loss is
            # sufficient to mark the device Online; do not classify every
            # reachable device as Idle/Unstable based only on latency/jitter.
            # Packet loss and failed probes still retain their normal meaning.
            if is_win:
                is_unstable = any_alive and (not alive or loss_pct > 0)
            else:
                is_unstable = any_alive and (not alive or is_high_latency or is_high_jitter or loss_pct > 0)

            # Power-save / idle signature: every ping is getting through
            # (0% loss this cycle) but average latency is high — treated as
            # the device simply being quiet (screen off, Wi-Fi power-save,
            # nothing actively pulling data) rather than a degraded
            # connection, REGARDLESS of how erratic the individual replies
            # within the burst are.
            #
            # This is a deliberate simplification, chosen over the
            # jitter/bimodal-baseline check this used to have: a device that
            # only briefly wakes its radio (checking a notification, a quick
            # sync) produces a mix of fast and slow replies in the same
            # burst — high jitter — even though nothing is wrong, so trying
            # to use jitter to tell "sleeping" apart from "flaky" was
            # misclassifying that common, normal case as Unstable.
            #
            # Trade-off worth knowing: 0% loss is the ONLY thing still
            # distinguishing Idle from Unstable here. A device with a
            # genuinely flaky link — wildly erratic latency from
            # interference or a weak signal, but that never happens to drop
            # a full packet this cycle — now also reads as Idle instead of
            # Unstable, since jitter no longer factors in at all. If that
            # starts hiding a real problem on some device, packet loss
            # (or a jitter check reinstated alongside it) is the signal to
            # bring back — not latency, which idle devices legitimately hit
            # too.
            # Loss tolerance for the Idle (power-save) signature: with only
            # SAMPLE_COUNT pings per cycle, ONE dropped packet alone already
            # reads as 10% loss this cycle — a radio waking from deep sleep
            # can easily miss the very first probe even though the device
            # is genuinely just idle, not degraded. Requiring a flat 0% here
            # made an unused, idle device flap Idle -> Unstable -> Idle every
            # time that happened, with nothing about the device actually
            # changing. Mirrors the latency hysteresis above: once already
            # Idle, one stray drop (up to ~1 packet's worth) is tolerated
            # before escalating to Unstable; from any other status, a fully
            # clean burst is still required to be called Idle in the first
            # place, so a real, newly-degraded device is still caught
            # immediately.
            one_packet_pct = 100 / SAMPLE_COUNT
            loss_tolerance = one_packet_pct + 1 if device.status == "Idle" else 0
            power_save_pattern = (
                not is_win and alive and loss_pct <= loss_tolerance and is_high_latency
            )


            pending_history = None  # set inside the lock if a transition
            # happened this cycle; the actual disk write runs AFTER the
            # lock is released (see below) — see next comment for why.
            became_offline = False
            # Recovery/transition messages destined for the Troubleshoot
            # Log are collected here instead of being sent immediately.
            # add_auto_troubleshoot_log() itself acquires self.lock — and
            # since self.lock is a plain (non-reentrant) threading.Lock,
            # calling it from inside the `with self.lock:` block below
            # would make this same thread block forever trying to
            # re-acquire a lock it's already holding. That deadlock never
            # releases self.lock, so every other place that does
            # `with engine.lock:` (the UI's refresh_panel, the periodic
            # stats refresh, etc.) then hangs forever too — freezing the
            # whole app. Queuing the messages here and sending them AFTER
            # the lock is released avoids that entirely.
            pending_auto_logs = []
            with self.lock:
                status_before = device.status
                # Alive this cycle — immediately reset fail_count so reconnect is instant
                if alive:
                    device.fail_count = 0


                if alive and not is_unstable:
                    prev_status = device.status

                    if prev_status == "Idle":
                        # Recovers on the first clean cycle, same as an
                        # Offline device. A device that answers once and
                        # goes quiet again simply drops back to Idle next
                        # cycle.
                        ts = datetime.now().strftime("%H:%M:%S")
                        pending_auto_logs.append(
                            f"[{ts}] >> RECOVERED: {device.name} ({device.ip}) is back online!"
                        )
                        device.status = "Online"
                        device.color = STATUS_COLORS["Online"]
                    else:
                        if prev_status == "Offline":
                            ts = datetime.now().strftime("%H:%M:%S")
                            # The dashboard Troubleshoot Log is backed by
                            # auto_troubleshoot_logs. Log natural recovery here
                            # so an Offline -> Online transition is always visible.
                            pending_auto_logs.append(
                                f"[{ts}] >> RECOVERED: {device.name} ({device.ip}) is back online!"
                            )
                            if hasattr(self, "_repair_running"):
                                self._repair_running.discard(device.ip)
                            if hasattr(self, "_last_repair"):
                                self._last_repair.pop(device.ip, None)
                        device.status = "Online"
                        device.color = STATUS_COLORS["Online"]


                elif alive and power_save_pattern:
                    # Answering every ping, no drops — just slow to reply,
                    # which is the classic sign of a screen-off device in
                    # Wi-Fi power-save rather than an actual network problem.
                    prev_status = device.status
                    if prev_status == "Offline":
                        ts = datetime.now().strftime("%H:%M:%S")
                        pending_auto_logs.append(
                            f"[{ts}] >> RECOVERED: {device.name} ({device.ip}) is reachable again, but is slow — marked Idle."
                        )
                    device.status = "Idle"
                    device.color = STATUS_COLORS["Idle"]

                elif alive and is_unstable:
                    # Responding but degraded — show unstable, log recovery if was offline
                    prev_status = device.status
                    if prev_status in ("Offline", "Idle"):
                        ts = datetime.now().strftime("%H:%M:%S")
                        pending_auto_logs.append(
                            f"[{ts}] >> RECOVERED: {device.name} ({device.ip}) is responding again, but is still unstable."
                        )
                        if hasattr(self, "_repair_running"):
                            self._repair_running.discard(device.ip)
                        if hasattr(self, "_last_repair"):
                            self._last_repair.pop(device.ip, None)
                    device.status = "Unstable"
                    device.color = STATUS_COLORS["Unstable"]
                    device.unstable_count = getattr(device, "unstable_count", 0) + 1


                elif not alive and tcp_reachable:
                    # ICMP got no replies at all, but a TCP port is still
                    # open — the device is genuinely present, just not
                    # answering ping (deep sleep / Wi-Fi power-save often
                    # still leaves a background service listening). That's
                    # exactly what "Idle" means here, so go straight there
                    # without waiting on a fail-count streak or a separate
                    # ARP check — TCP already proves it's still connected.
                    device.fail_count = 0
                    prev_status = device.status
                    if prev_status == "Offline":
                        ts = datetime.now().strftime("%H:%M:%S")
                        pending_auto_logs.append(
                            f"[{ts}] >> RECOVERED: {device.name} ({device.ip}) is reachable again via TCP but not ping — marked Idle."
                        )
                    device.status = "Idle"
                    device.color = STATUS_COLORS["Idle"]

                elif not alive and loss_pct == 100:
                    # Hard offline signal: 100% packet loss this cycle. Before
                    # committing to "Offline", check ARP — if the device still
                    # answers at Layer 2, it's very likely still connected and
                    # just not responding to ICMP (deep sleep/power-save), so
                    # it gets the softer "Idle" label instead of a flat
                    # "Offline". No 3-strike wait either way — this cycle's
                    # result already fully determines which of the two it is.
                    device.fail_count = getattr(device, "fail_count", 0) + 1
                    # _arp_still_present() runs several blocking subprocess
                    # calls (arp -d, a ping probe, arp -a) that can each take
                    # up to a few seconds. Calling it here while still
                    # holding self.lock is exactly the "freeze the whole
                    # app" trap _arp_still_present's own comment warns
                    # about — every device going Offline/Unstable at once
                    # (common on a busy/large network) would queue up behind
                    # this lock, blocking the UI's refresh_panel and every
                    # other device's own status update along with it.
                    # Release the lock for the duration of the check, same
                    # as the disk write further below does for the same
                    # reason, then reacquire before touching device state.
                    self.lock.release()
                    try:
                        arp_present = _arp_still_present(device.ip)
                    finally:
                        self.lock.acquire()
                    if arp_present:
                        device.status = "Idle"
                        device.color = STATUS_COLORS["Idle"]
                    else:
                        device.status = "Offline"
                        device.color = STATUS_COLORS["Offline"]


                elif not alive and not all_dead:
                    # No ICMP reply, but there may still be a live device on
                    # the network. Confirm presence immediately instead of
                    # temporarily labeling it Unstable. If ARP still sees the
                    # device, there is no valid active measurement, so Idle is
                    # the appropriate status. Only use Unstable when the
                    # device is actually responding but degraded.
                    device.fail_count = getattr(device, "fail_count", 0) + 1
                    self.lock.release()
                    try:
                        arp_present = _arp_still_present(device.ip)
                    finally:
                        self.lock.acquire()
                    if arp_present:
                        device.fail_count = 0
                        device.status = "Idle"
                        device.color = STATUS_COLORS["Idle"]
                    else:
                        device.status = "Offline"
                        device.color = STATUS_COLORS["Offline"]


                else:
                    # All probes are currently unanswered. Confirm whether
                    # the device is still present on the local network. A
                    # confirmed device with no usable ICMP measurement is
                    # Idle; only a device that cannot be confirmed at all is
                    # Offline. This avoids showing Unstable with --/--/100%/--.
                    device.fail_count = getattr(device, "fail_count", 0) + 1
                    self.lock.release()
                    try:
                        arp_present = _arp_still_present(device.ip)
                    finally:
                        self.lock.acquire()
                    if arp_present:
                        device.fail_count = 0
                        device.status = "Idle"
                        device.color = STATUS_COLORS["Idle"]
                    else:
                        device.status = "Offline"
                        device.color = STATUS_COLORS["Offline"]


                # Idle is reached two different ways above: one where the
                # device answered every ping this cycle and is just slow
                # (power_save_pattern) — which left a real, live
                # latency/jitter/speed/0%-loss reading in place from the
                # "Write live stats" step earlier — and one where it didn't
                # answer ICMP at all this cycle (100% loss already,
                # "--" already in place) but is still confirmed present via
                # ARP or an open TCP port. Showing real numbers for the
                # first kind and blanks for the second made "Idle" look
                # like two different statuses depending on which detection
                # path happened to fire. Idle is meant to mean the same
                # thing either way — "not treated as a live, measured
                # connection right now" — so force the same display for
                # both: no live reading shown, 100% loss, regardless of
                # what this cycle's own ping actually returned.
                if device.status == "Idle":
                    device.latency = "--"
                    device.jitter = "--"
                    # Network Speed is intentionally NOT blanked here anymore:
                    # if an Idle device still produced a fresh speed reading
                    # this cycle ("Write live stats" above already set the
                    # display to that reading, or to "--" when there was
                    # none / the device didn't answer), keep showing it. The
                    # bandwidth estimate uses the same reading, so display
                    # and bandwidth stay consistent.
                    device.packet_loss = "100%"


                # Simple history log: whenever a device newly flags as
                # Unstable, Idle, or Offline, record when it happened and
                # what its data looked like at that moment. Also logs the
                # moment it recovers back to Online — but only when the
                # PREVIOUS status was actually one of those problem states,
                # so this never fires for devices that are simply online as
                # normal. That keeps the timeline as pairs of "went bad" /
                # "recovered" events, not a running log of every online
                # device. Still only logs on the actual transition (not
                # every cycle it stays in a state), so this stays a
                # readable timeline rather than a noisy dump of every
                # single health check.
                is_recovery = device.status == "Online" and status_before in ("Unstable", "Idle", "Offline")
                if device.status != status_before and (device.status in ("Unstable", "Idle", "Offline") or is_recovery):
                    if not hasattr(device, "status_history"):
                        device.status_history = []
                    history_entry = {
                        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "status": device.status,
                        "latency": device.latency,
                        "jitter": device.jitter,
                        "packet_loss": device.packet_loss,
                        "network_speed": getattr(device, "network_speed", "--"),
                    }
                    device.status_history.append(history_entry)
                    if len(device.status_history) > 100:
                        device.status_history.pop(0)
                    # Don't write to disk here — this is still inside
                    # self.lock, which the UI needs every ~2s to read
                    # device data for the dashboard. history_store's
                    # append_entry() does a full JSON read+write to disk,
                    # which can take real time (bigger the saved history,
                    # slower it gets) — doing that while holding self.lock
                    # freezes this network's ENTIRE panel until it finishes.
                    # Just remember what to save; the actual write happens
                    # right after this lock is released, below.
                    pending_history = (self.network_key, device.mac, device.ip, device.name, history_entry)

                # Automatic offline detection: this fires exactly once when
                # a device changes into Offline. It does NOT fire again on
                # every polling cycle while the device remains offline.
                became_offline = (device.status == "Offline" and status_before != "Offline")


            # Now that self.lock is released, do the (potentially slow)
            # disk write. The UI can read fresh device data again
            # immediately — it's no longer stuck waiting behind a file I/O
            # operation it has nothing to do with.
            if pending_history:
                history_store.append_entry(*pending_history)

            # Same reasoning as pending_history above: send any recovery
            # log lines queued while the lock was held, now that it's free.
            for msg in pending_auto_logs:
                self.add_auto_troubleshoot_log(msg, device=device)

            # The system itself detected the device going offline. Print the
            # alert immediately in THIS network's bottom Troubleshoot Log,
            # identify the exact device, and start the automatic repair path.
            # This is intentionally outside self.lock so the repair thread
            # never blocks the monitoring loop.
            if became_offline:
                ts = datetime.now().strftime("%H:%M:%S")
                self.add_auto_troubleshoot_log(
                    f"[{ts}] !! OFFLINE DEVICE DETECTED: {device.name} ({device.ip})",
                    device=device
                )
                self.trigger_auto_repair(device)


        # Staggered starts: firing every device's ping in the exact same
        # instant floods the host's own uplink for a brief moment, which
        # can spike latency/jitter on EVERY device at once — noise from
        # the measurement itself, not the network. Spreading starts out
        # in small waves (with a touch of random jitter so devices don't
        # lock-step into their own mini-bursts) avoids that self-induced
        # congestion while staying well within the loop's 2s cadence.
        #
        # Dispatched through the bounded pool (self._health_pool) instead
        # of one raw thread per device — see its creation in __init__ for
        # why: with many devices, unbounded threads meant unbounded
        # concurrent subprocess spawns, which is what caused lag/crashes
        # on larger networks. The pool caps how much can run at once;
        # extra devices simply wait their turn for a free worker instead
        # of piling on more OS-level load.
        # In-flight guard: skip re-submitting a device whose PREVIOUS
        # check hasn't finished yet. Without this, a device count that
        # outpaces what the pool can get through inside one 2s cadence
        # (heavy devices — high loss, no response — take longer per
        # check) meant every cycle kept adding a fresh batch of tasks on
        # top of whatever was still queued/running from earlier cycles,
        # so the backlog only ever grew, never drained — that unbounded
        # queue growth, not the pool's own worker cap, was the real
        # source of the lag on larger networks. This cheap flag makes a
        # busy device's slot simply wait for its own next free cycle
        # instead of stacking another copy of itself behind it.
        self._resize_health_pool(len(self.devices))
        futures = []
        for i, dev in enumerate(self.devices):
            # Member of a paused group: don't probe it at all. Clearing
            # _bw_last_ts means the first check after RESUME doesn't
            # integrate the whole paused gap as if it were used bandwidth.
            if self.paused_macs and group_store.normalize_mac(dev.mac) in self.paused_macs:
                dev._bw_last_ts = None
                continue
            if getattr(dev, "_health_check_in_flight", False):
                continue
            dev._health_check_in_flight = True
            delay = (i % 8) * 0.05 + random.uniform(0, 0.03)

            def _staggered_check(d=dev, wait=delay):
                if wait:
                    time.sleep(wait)
                try:
                    check_device(d)
                finally:
                    d._health_check_in_flight = False

            futures.append(self._health_pool.submit(_staggered_check))
        # This call BLOCKS the whole loop until every device is done or the
        # timeout hits, and the loop then sleeps another 2s — so the real
        # cycle length is (slowest device, capped here) + 2s, for EVERY
        # device on this network. A healthy device finishes in ~1-2s, but
        # an offline/idle one that never answers can take 5s+ (a 0.3s
        # timeout per ICMP sample, TCP port checks, then the ARP check).
        # With the old 4s cap, a single such device stretched every
        # cycle to ~6s and made every other device's readings (speed
        # included) look like they'd stalled. 2.5s still comfortably
        # covers a healthy device, while a straggler simply keeps going in
        # the background (the in-flight guard above stops it being
        # re-submitted) and lands in a later refresh — it no longer
        # delays anyone else.
        concurrent.futures.wait(futures, timeout=2.5)


        # ── Network-wide spike detection ────────────────────────────
        # If a large share of devices are degraded at the same moment,
        # the common cause is usually upstream (the router, or the
        # host's own uplink) rather than every device coincidentally
        # having its own separate problem — flag it so the UI can tell
        # the person their readings may be temporarily less trustworthy
        # right now, instead of quietly presenting them as equally solid.
        with self.lock:
            total    = len(self.devices)
            degraded = sum(1 for d in self.devices if d.status in ("Unstable", "Offline"))


        meets_condition = total >= 3 and (degraded / total) >= 0.8


        # The condition has to hold (or clear) for 3 consecutive cycles
        # before the banner flips. The 80% threshold reduces alerts when only
        # a portion of devices are degraded; the debounce also filters brief
        # status changes. This can miss problems affecting fewer devices.
        if meets_condition:
            self._network_wide_on_streak += 1
            self._network_wide_off_streak = 0
        else:
            self._network_wide_off_streak += 1
            self._network_wide_on_streak = 0


        was_issue = self.network_wide_issue
        if not was_issue and self._network_wide_on_streak >= 3:
            self.network_wide_issue = True
            self.network_wide_since = datetime.now().strftime("%H:%M:%S")
            self.add_troubleshoot_log(
                f"[{self.network_wide_since}] NETWORK-WIDE LATENCY SPIKE DETECTED — "
                f"{degraded}/{total} devices degraded at once. Likely an upstream/router "
                f"issue, not individual devices. System is degraded — monitoring closely "
                f"and applying automatic fixes as devices drop offline."
            )
        elif was_issue and self._network_wide_off_streak >= 3:
            self.network_wide_issue = False
            ts = datetime.now().strftime("%H:%M:%S")
            self.add_troubleshoot_log(
                f"[{ts}] Network-wide latency spike cleared — network is back to normal. Fixed."
            )
            self.network_wide_since = None


        self.ui.after(0, lambda: self.ui.request_panel_refresh(self))


    def trigger_auto_repair(self, device):
        """Start the dedicated automatic troubleshoot flow for a device that
        has just transitioned to Offline.

        Automatic troubleshooting is completely independent from manual
        DIAGNOSE. Offline detection itself is the trigger.
        """
        now = time.time()
        if not hasattr(self, "_last_repair"):
            self._last_repair = {}
        if not hasattr(self, "_repair_running"):
            self._repair_running = set()

        ip = device.ip
        if ip in self._repair_running:
            return
        if now - self._last_repair.get(ip, 0) < 60:
            return

        self._last_repair[ip] = now
        self._repair_running.add(ip)

        ts = datetime.now().strftime("%H:%M:%S")
        self.add_auto_troubleshoot_log(
            f"[{ts}] >> AUTO-TROUBLESHOOT STARTED FOR: {device.name} ({ip})",
            device=device
        )

        def finish(recovered):
            self._repair_running.discard(ip)
            if recovered:
                self._last_repair.pop(ip, None)
                device.fail_count = 0

        def troubleshoot_complete(recovered):
            ts2 = datetime.now().strftime("%H:%M:%S")
            if recovered:
                self.add_auto_troubleshoot_log(
                    f"[{ts2}] >> RECOVERED: {device.name} ({ip}) is back online!",
                    device=device
                )
            else:
                self.add_auto_troubleshoot_log(
                    f"[{ts2}] >> UNRESOLVED: {device.name} ({ip}) is still offline.",
                    device=device
                )
            finish(recovered)

        self.run_troubleshoot(
            device,
            on_progress=None,
            on_complete=troubleshoot_complete,
            clear_log=False,
        )


    def run_manual_diagnostic(self, device):
        # Freeze monitoring for accurate snapshot
        self.paused = True
        self.ui.update_status(f"PAUSED - ANALYZING: {device.ip}...", "#3399FF", "white")
        self.add_troubleshoot_log(f"DIAGNOSTIC STARTED FOR {device.ip}")


        def on_close():
            self.paused = False
            self.ui.update_status("MONITOR ACTIVE", "#00CC66", "black")
            self.add_troubleshoot_log(f"MONITORING RESUMED.")


        def diagnostic_task():
            is_win = platform.system().lower() == "windows"
            is_mac_os = platform.system().lower() == "darwin"
            param = "-n" if is_win else "-c"
            timeout_flag = "-w" if is_win else "-W"


            # Snapshot status BEFORE running pings (monitoring is frozen)
            snapshot_status = device.status


            DIAGNOSTIC_SAMPLE_COUNT = 10
            cmd = ["ping", param, str(DIAGNOSTIC_SAMPLE_COUNT), timeout_flag, "1000", device.ip]


            try:
                process = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, _ = process.communicate()


                times = _parse_ping_times(stdout)


                report = f"NETWORK AUDIT REPORT: {device.name}\n"
                report += "=" * 40 + "\n"
                report += f"Target IP:  {device.ip}\n"
                report += f"Status:     {snapshot_status}\n"
                report += f"Timestamp:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                report += "=" * 40 + "\n\n"


                if not times:
                    arp_seen = False
                    try:
                        _enc = "cp1252" if is_win else "utf-8"
                        try:
                            if is_win or is_mac_os:
                                _run(["arp", "-d", device.ip], capture_output=True, text=True,
                                     encoding=_enc, errors="replace")
                            else:
                                _run(["ip", "neigh", "del", device.ip], capture_output=True, text=True,
                                     encoding=_enc, errors="replace")
                        except Exception:
                            pass
                        _run(["ping", param, "1", timeout_flag, "500", device.ip],
                             capture_output=True, text=True, encoding=_enc, errors="replace",
                             timeout=3)
                        arp_cmd = ["arp", "-a"] if (is_win) else ["arp", "-an"]
                        arp_out = _run(arp_cmd, capture_output=True, text=True,
                                        encoding=_enc, errors="replace", timeout=3).stdout
                        arp_seen = any(device.ip in line for line in arp_out.splitlines())
                    except Exception:
                        pass


                    if arp_seen:
                        report += "RESULT: [ IDLE - NOT RESPONDING, LIKELY ASLEEP ]\n\n"
                        report += "DIAGNOSIS:\n"
                        report += "  Device did not respond to any ICMP Echo requests, but it\n"
                        report += "  still has a live ARP entry — its network adapter is answering\n"
                        report += "  at Layer 2, which usually means it's still connected to the\n"
                        report += "  network and simply not responding at the application level\n"
                        report += "  (commonly Wi-Fi power-save / deep sleep).\n\n"
                        report += "POSSIBLE CAUSES:\n"
                        report += "  - Device is asleep/idle with its screen off.\n"
                        report += "  - Wi-Fi power-save mode delaying/dropping replies.\n"
                        report += "  - Firewall on the device blocking ICMP specifically.\n\n"
                        report += "RECOMMENDED ACTIONS:\n"
                        report += "  1. Wake the device (unlock screen / touch input) and re-diagnose.\n"
                        report += "  2. If it stays this way, verify it manually before assuming it's down.\n"
                    else:
                        report += "RESULT: [ OFFLINE - UNREACHABLE ]\n\n"
                        report += "DIAGNOSIS:\n"
                        report += "  Device did not respond to any ICMP Echo requests, and it has\n"
                        report += "  no ARP entry either — its network adapter isn't answering at\n"
                        report += "  all, which is a stronger sign it's actually disconnected.\n\n"
                        report += "POSSIBLE CAUSES:\n"
                        report += "  - Device is powered off or in sleep mode.\n"
                        report += "  - Network cable unplugged or Wi-Fi disconnected.\n"
                        report += "  - Firewall is blocking all ICMP traffic.\n"
                        report += "  - Device IP has changed (ARP cache stale).\n\n"
                        report += "RECOMMENDED ACTIONS:\n"
                        report += "  1. Verify the device is powered ON.\n"
                        report += "  2. Check physical Ethernet or Wi-Fi connection.\n"
                        report += "  3. Try pinging the device manually from CMD/Terminal.\n"
                        report += "  4. Check if firewall rules are blocking ICMP.\n"
                else:
                    total_sent = DIAGNOSTIC_SAMPLE_COUNT
                    avg_lat = statistics.median(times)
                    max_lat = max(times)
                    min_lat = min(times)
                    loss = ((total_sent - len(times)) / total_sent) * 100
                    jitter_diffs = [abs(times[i] - times[i - 1]) for i in range(1, len(times))]
                    jitter = (sum(jitter_diffs) / len(jitter_diffs)) if jitter_diffs else 0


                    if snapshot_status == "Unstable":
                        report += "RESULT: [ UNSTABLE - CONNECTION DEGRADED ]\n\n"
                    elif snapshot_status == "Idle":
                        report += "RESULT: [ IDLE - NOT RESPONDING, LIKELY ASLEEP ]\n\n"
                    elif snapshot_status == "Offline":
                        report += "RESULT: [ OFFLINE - UNREACHABLE ]\n\n"
                    else:
                        report += "RESULT: [ ONLINE - CONNECTION STABLE ]\n\n"


                    report += "CONNECTION STATISTICS:\n"
                    report += f"  Packets Sent:  {total_sent}\n"
                    report += f"  Packets Lost:  {total_sent - len(times)} ({loss:.0f}%)\n"
                    report += f"  Avg Latency:   {avg_lat:.2f} ms\n"
                    report += f"  Min Latency:   {min_lat:.2f} ms\n"
                    report += f"  Max Latency:   {max_lat:.2f} ms\n"
                    report += f"  Jitter:        {jitter:.2f} ms\n\n"


                    report += "SYSTEM EVALUATION:\n"
                    issues = []


                    if snapshot_status == "Online":
                        report += "  [OK] OPTIMAL: Connection is stable and performing well.\n"
                        report += "  No issues detected. Device is healthy.\n"
                    else:
                        if loss >= 40:
                            issues.append(("CRITICAL", "High packet loss detected.", [
                                "Severe network congestion or interference.",
                                "Faulty network cable or loose connection.",
                                "Overloaded switch or router port.",
                            ], [
                                "Check and replace the network cable.",
                                "Reduce network load or check for bandwidth hogs.",
                                "Restart the switch port or router.",
                            ]))
                        elif loss > 0:
                            issues.append(("WARNING", f"Packet loss detected ({loss:.0f}%).", [
                                "Intermittent network interference.",
                                "Wi-Fi signal degradation or channel congestion.",
                            ], [
                                "Move device closer to the access point if on Wi-Fi.",
                                "Switch to a less congested Wi-Fi channel.",
                            ]))


                        if avg_lat > 300:
                            issues.append(("CRITICAL", f"Extremely high latency ({avg_lat:.0f}ms).", [
                                "Severe network congestion.",
                                "Device CPU or resources overloaded.",
                            ], [
                                "Restart the device and router.",
                                "Check for heavy background processes on the device.",
                            ]))
                        elif avg_lat > 150:
                            issues.append(("WARNING", f"High latency ({avg_lat:.0f}ms).", [
                                "Network congestion or heavy traffic.",
                                "Weak Wi-Fi signal.",
                            ], [
                                "Check network utilization on the router.",
                                "Move device closer to the Wi-Fi access point.",
                            ]))


                        if jitter > 30:
                            issues.append(("WARNING", f"Very high jitter ({jitter:.0f}ms).", [
                                "Inconsistent network path or routing changes.",
                                "Wireless interference from other devices.",
                            ], [
                                "Use a wired connection instead of Wi-Fi.",
                                "Check for wireless interference.",
                            ]))
                        elif jitter > 20:
                            issues.append(("NOTICE", f"Elevated jitter ({jitter:.0f}ms).", [
                                "Minor network instability.",
                            ], [
                                "Monitor the device over time.",
                            ]))


                        if not issues:
                            report += "  [OK] OPTIMAL: Connection is stable and performing well.\n"
                            report += "  No issues detected. Device is healthy.\n"
                        else:
                            for level, summary, causes, actions in issues:
                                icon = "[X]" if level == "CRITICAL" else "[!]" if level == "WARNING" else "[i]"
                                report += f"  {icon} {level}: {summary}\n"
                                report += "    Possible Causes:\n"
                                for c in causes:
                                    report += f"      - {c}\n"
                                report += "    Recommended Actions:\n"
                                for a in actions:
                                    report += f"      -> {a}\n"
                                report += "\n"


                self.ui.after(0, lambda: self.ui.show_diagnostic(report, on_close))


            except Exception as e:
                on_close()
                self.ui.after(0, lambda: self.ui.show_info("Diagnostic Error", f"Engine Failure: {str(e)}"))


        threading.Thread(target=diagnostic_task, daemon=True).start()


    def get_diagnostic_snapshot(self, device):
        """Return a plain data snapshot for one device — raw readings only,
        no cause/action suggestions. Used by the per-device DIAGNOSE popup;
        troubleshooting suggestions stay in the activity log via
        add_troubleshoot_log / trigger_auto_repair."""
        with self.lock:
            history = list(getattr(device, "ping_history", []))
            snapshot = {
                "Name":            device.name,
                "IP Address":      device.ip,
                "MAC Address":     device.mac,
                "Status":          device.status,
                "Latency":         getattr(device, "latency", "--"),
                "TCP Latency":     getattr(device, "tcp_latency", "--"),
                "Jitter":          getattr(device, "jitter", "--"),
                "Packet Loss":     getattr(device, "packet_loss", "--"),
                "Network Speed":   getattr(device, "network_speed", "--"),
                "Last Checked":    getattr(device, "last_check", "--:--:--"),
                "Fail Count":      getattr(device, "fail_count", 0),
                "Unstable Count":  getattr(device, "unstable_count", 0),
                "Gateway":         self.gateway_ip,
                "Network":         self.label,
            }
        if history:
            recent = ", ".join(
                ("UP" if alive else "DOWN") + f" ({lat:.0f}ms/{jit:.0f}ms jitter/{loss}% loss)"
                for alive, lat, jit, loss in history
            )
            snapshot["Recent Pings"] = recent
        else:
            snapshot["Recent Pings"] = "--"
        return snapshot


    def run_diagnostic(self, device, on_complete, on_progress=None):
        """On-demand, read-only diagnostic sweep for one device — runs ONLY
        when the DIAGNOSE button is clicked. Never writes to the activity
        log / troubleshoot panel. Hands raw findings back to on_complete()
        once finished so the UI can display them (data only, no
        cause/action suggestions).


        If on_progress is given, it's called with a short status string
        right before each individual check starts, so the UI can show
        what's currently happening while the sweep runs."""
        def _step(msg):
            if on_progress:
                self.ui.after(0, lambda m=msg: on_progress(m))


        def _task():
            is_win       = platform.system().lower() == "windows"
            is_mac_os    = platform.system().lower() == "darwin"
            param        = "-n" if is_win else "-c"
            timeout_flag = "-w" if is_win else "-W"
            _enc         = "cp1252" if is_win else "utf-8"
            ip = device.ip
            results = {}


            # ICMP Ping — ground truth first: send the echoes ourselves via
            # Scapy and time each round trip with a high-resolution clock.
            # This is the same method the background health-check loop uses,
            # and it avoids two real accuracy problems with parsing the OS
            # ping tool's own text: Windows rounds "time=Xms" to whole
            # milliseconds (no decimals), and every platform's ping binary
            # is running its own timer, not one we control end-to-end. Falls
            # back to the OS ping tool only when Scapy isn't installed or
            # can't send raw packets here (needs root/admin, plus Npcap on
            # Windows) — same fallback condition as the health-check loop.
            _step("Pinging device...")
            PING_SAMPLES = 4
            scapy_status, scapy_latencies = _scapy_icmp_ping(ip, count=PING_SAMPLES, timeout=0.25)
            if scapy_status == "ok":
                times = scapy_latencies
                if times:
                    avg_lat = sum(times) / len(times)
                    loss    = round(100 * (PING_SAMPLES - len(times)) / PING_SAMPLES)
                    jitter  = round(statistics.stdev(times), 1) if len(times) > 1 else 0
                    results["ICMP Ping"] = f"{avg_lat:.0f}ms avg / {loss}% loss / {jitter}ms jitter"
                else:
                    results["ICMP Ping"] = "No response"
            else:
                ping_result = _run(["ping", param, str(PING_SAMPLES), timeout_flag, "1000", ip],
                                    capture_output=True, text=True, encoding=_enc, errors="replace",
                                    timeout=PING_SAMPLES + 3)
                ping_out = ping_result.stdout + ping_result.stderr
                ping_ok  = ping_result.returncode == 0
                times = _parse_ping_times(ping_out)
                loss_m = re.search(r"([\d\.]+)%\s*(?:packet\s*)?loss", ping_out, re.IGNORECASE)
                if ping_ok and times:
                    avg_lat = sum(times) / len(times)
                    loss    = round(float(loss_m.group(1))) if loss_m else round(((PING_SAMPLES - len(times)) / PING_SAMPLES) * 100)
                    jitter  = round(statistics.stdev(times), 1) if len(times) > 1 else 0
                    results["ICMP Ping"] = f"{avg_lat:.0f}ms avg / {loss}% loss / {jitter}ms jitter"
                else:
                    results["ICMP Ping"] = "No response"


            # ARP Table — ground truth first: send a real ARP request via
            # Scapy and wait for a genuine reply. This bypasses the OS's
            # ARP cache entirely, so it can't return a stale MAC left over
            # from a device that's since disconnected, and it can't miss a
            # device that just joined. Falls back to reading the OS's ARP
            # table only when Scapy isn't installed or can't send raw
            # packets here (needs root/admin, plus Npcap on Windows).
            _step("Reading ARP table...")
            scapy_status, scapy_mac = _scapy_arp_resolve(ip, timeout=0.8)
            if scapy_status == "ok":
                if scapy_mac and device.mac and scapy_mac != device.mac.lower():
                    results["ARP Table"] = f"Mismatch — expected {device.mac}, found {scapy_mac}"
                elif scapy_mac:
                    results["ARP Table"] = f"{ip} -> {scapy_mac}"
                else:
                    results["ARP Table"] = "No ARP entry found"
            else:
                try:
                    # Force a fresh resolution instead of trusting whatever
                    # the OS happened to have cached: clear any existing
                    # entry for this IP, then send one probe to trigger a
                    # brand-new ARP resolution before reading the table.
                    try:
                        if is_win or is_mac_os:
                            _run(["arp", "-d", ip], capture_output=True, text=True,
                                 encoding=_enc, errors="replace")
                        else:
                            _run(["ip", "neigh", "del", ip], capture_output=True, text=True,
                                 encoding=_enc, errors="replace")
                    except Exception:
                        pass
                    _run(["ping", param, "1", timeout_flag, "500", ip],
                         capture_output=True, text=True, encoding=_enc, errors="replace",
                         timeout=3)

                    arp_cmd = ["arp", "-a"] if (is_win) else ["arp", "-an"]
                    arp_out = _run(arp_cmd, capture_output=True, text=True,
                                    encoding=_enc, errors="replace", timeout=3).stdout
                    arp_mac = None
                    for line in arp_out.splitlines():
                        if ip not in line:
                            continue
                        # A disconnected device's entry can linger as an
                        # unresolved row (e.g. "<incomplete>" on Linux/macOS,
                        # a stale row on Windows) that still contains the IP
                        # string — skip those instead of misreading them as
                        # a live, resolved entry.
                        if "incomplete" in line.lower() or "failed" in line.lower():
                            continue
                        m = re.search(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                                      r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})", line)
                        if m:
                            arp_mac = m.group(1).replace("-", ":").lower()
                        break
                    if arp_mac and device.mac and arp_mac != device.mac.lower():
                        results["ARP Table"] = f"Mismatch — expected {device.mac}, found {arp_mac}"
                    elif arp_mac:
                        results["ARP Table"] = f"{ip} -> {arp_mac}"
                    else:
                        results["ARP Table"] = "No ARP entry found"
                except Exception:
                    results["ARP Table"] = "Check failed"


            # TCP Port Scan
            _step("Scanning common TCP ports...")
            port_map = {22: "SSH", 80: "HTTP", 139: "NetBIOS", 443: "HTTPS",
                        445: "SMB", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt"}
            open_ports = []
            for port, label in port_map.items():
                try:
                    with socket.create_connection((ip, port), timeout=0.5):
                        open_ports.append(f"{port}/{label}")
                except Exception:
                    pass
            results["Open TCP Ports"] = ", ".join(open_ports) if open_ports else "None responded"


            # Reverse DNS
            _step("Resolving reverse DNS...")
            try:
                results["Reverse DNS"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                results["Reverse DNS"] = "No hostname found"


            # Gateway Reachability — a single ICMP probe is noisy enough to
            # misreport a healthy gateway as unreachable on one dropped
            # packet, so this sends a few probes per gateway and only
            # calls it unreachable if every one of them goes unanswered.
            # Ground truth first via Scapy (bypasses the OS ping tool's
            # own retry/timeout behavior); falls back to a couple of OS
            # ping attempts when Scapy isn't usable here.
            _step("Testing gateway reachability...")
            gw_list = list(self.gateways) if self.gateways else (
                [self.gateway_ip] if self.gateway_ip != "UNKNOWN" else [])
            gw_ok = False
            for _gw in gw_list:
                gw_status, gw_latencies = _scapy_icmp_ping(_gw, count=3, timeout=0.3)
                if gw_status == "ok":
                    if gw_latencies:
                        gw_ok = True
                        break
                    continue
                for _ in range(2):
                    if _run(["ping", param, "1", timeout_flag, "500", _gw],
                            capture_output=True, timeout=3).returncode == 0:
                        gw_ok = True
                        break
                if gw_ok:
                    break
            results["Gateway Reachability"] = "Reachable" if gw_ok else "Unreachable"


            # Turn this sweep's raw findings + the device's live health
            # numbers into a short, human-readable list of likely causes.
            # Tucked under a leading-underscore key so it's easy for the UI
            # to pull out and render separately from the plain data table,
            # without polluting HIDDEN_FIELDS or the field-iteration logic.
            results["_possible_causes"] = self._analyze_possible_causes(device, results)


            self.ui.after(0, lambda: on_complete(results))


        threading.Thread(target=_task, daemon=True).start()


    def _analyze_possible_causes(self, device, results):
        """Best-effort, human-readable explanations for why a device is
        currently in its present status, built from this diagnostic
        sweep's findings (results) plus the device's own live health
        numbers. Purely explanatory: it never suggests or takes an action
        (that stays in run_troubleshoot); it simply narrows down what is
        most likely occurring. Offline, Unstable, Idle, and Online each
        receive different checks, since the relevant signal differs for
        each status. Returns a list of {"text", "level"} dicts, ordered
        with the most likely cause first; "level" is "critical",
        "warning", or "info" so the UI can color-code each entry."""
        with self.lock:
            status          = device.status
            packet_loss     = getattr(device, "packet_loss", "--")
            jitter          = getattr(device, "jitter", "--")
            latency         = getattr(device, "latency", "--")
            fail_count      = getattr(device, "fail_count", 0)
            unstable_count  = getattr(device, "unstable_count", 0)
            history         = list(getattr(device, "ping_history", []))

        def _num(val):
            try:
                return float(re.sub(r"[^\d.]", "", str(val)))
            except Exception:
                return None

        arp   = results.get("ARP Table", "") or ""
        icmp  = results.get("ICMP Ping", "") or ""
        gw    = results.get("Gateway Reachability", "") or ""
        ports = results.get("Open TCP Ports", "") or ""

        causes = []  # list of (level, text)

        if status == "Offline":
            if gw == "Unreachable":
                causes.append(("critical",
                    "The gateway is currently unreachable. This suggests the "
                    "issue originates upstream, such as with the router, "
                    "modem, or this machine's own network connection, rather "
                    "than with this specific device."))
            elif arp.startswith("No ARP entry"):
                causes.append(("critical",
                    "The device is not responding to ARP requests at all. "
                    "This is the strongest indicator that it is powered "
                    "off, disconnected, or out of Wi-Fi range, as opposed "
                    "to simply being slow to respond."))
            elif arp.startswith("Mismatch"):
                causes.append(("warning",
                    f"The MAC address currently seen at {device.ip} does "
                    "not match this device's expected MAC address. Another "
                    "device may have acquired this IP, or this device's own "
                    "MAC address has changed."))
            elif "->" in arp:
                causes.append(("warning",
                    "The device still responds to ARP, confirming it is on "
                    "the network, but it is not responding to pings. This "
                    "is often caused by a host firewall blocking ICMP "
                    "traffic, or by an unresponsive OS or network stack."))
            if ports and ports != "None responded":
                causes.append(("info",
                    f"Some TCP ports remain open ({ports}) despite the "
                    "failed ping. The device may still be reachable for "
                    "specific services even though ICMP traffic is blocked "
                    "or dropped."))
            if fail_count >= 3:
                causes.append(("info",
                    f"The device has failed {fail_count} consecutive health "
                    "checks, indicating a sustained outage rather than a "
                    "single dropped packet."))
            if not causes:
                causes.append(("info",
                    "No additional signal is available beyond the failed "
                    "ping itself. This should be treated as a hard outage "
                    "until the device responds again."))

        elif status == "Unstable":
            loss = _num(packet_loss)
            jit  = _num(jitter)
            lat  = _num(latency)
            if loss is not None and 0 < loss < 100:
                causes.append(("warning",
                    f"Partial packet loss was recorded this cycle "
                    f"({packet_loss}). Some pings are getting through while "
                    "others are not, which usually points to a weak or "
                    "marginal connection, such as a poor Wi-Fi signal or a "
                    "worn cable, rather than a full outage."))
            if jit is not None and jit > 40:
                causes.append(("warning",
                    f"Jitter is elevated ({jitter}), meaning round-trip "
                    "times are inconsistent. This is often caused by "
                    "network congestion, interference, or an unstable "
                    "wireless connection."))
            if lat is not None and lat > 150:
                causes.append(("info",
                    f"Average latency ({latency}) exceeds the 150ms "
                    "threshold used to flag instability."))
            if history and any(not h[0] for h in history) and any(h[0] for h in history):
                causes.append(("info",
                    "Recent pings show a mix of successful replies and "
                    "drops, indicating the device is intermittently losing "
                    "and regaining reachability rather than staying down."))
            if unstable_count >= 3:
                causes.append(("info",
                    f"This device has been flagged Unstable {unstable_count} "
                    "times so far, indicating a recurring pattern rather "
                    "than a one-time occurrence."))
            if not causes:
                causes.append(("info",
                    "The device is currently flagged Unstable based on this "
                    "cycle's readings, though no single dominant cause "
                    "stood out."))

        elif status == "Idle":
            if icmp == "No response" and ports and ports != "None responded":
                causes.append(("info",
                    "The device is not responding to ICMP pings but "
                    "remains reachable at a lower level through open TCP "
                    "ports. This is a typical sign of a screen-off phone or "
                    "laptop, or a device in Wi-Fi power-save mode, rather "
                    "than an actual disconnection."))
            elif icmp == "No response" and "->" in arp:
                causes.append(("info",
                    "The device is not responding to ICMP pings but still "
                    "answers ARP requests, confirming it remains present on "
                    "the network. It is simply not replying to pings at the "
                    "moment, which is common in power-save mode."))
            loss = _num(packet_loss)
            lat  = _num(latency)
            if loss == 0 and lat is not None and lat > 150:
                causes.append(("info",
                    f"Packet loss is at 0%, but latency is elevated "
                    f"({latency}). This is consistent with a device "
                    "delaying replies until its next power-save wake "
                    "cycle, rather than an actual connectivity problem."))
            if not causes:
                causes.append(("info",
                    "The device is marked Idle rather than Offline because "
                    "it still responds at a level below ICMP. This "
                    "typically resolves on its own once the device is "
                    "actively used again."))

        else:  # Online
            lat = _num(latency)
            if lat is not None and lat > 80:
                causes.append(("info",
                    f"Latency ({latency}) is somewhat higher than ideal, "
                    "though still within an acceptable range. This is "
                    "worth monitoring if it continues to increase."))
            if unstable_count > 0 or fail_count > 0:
                causes.append(("info",
                    "The device is currently healthy, but it has a history "
                    f"of flagged issues (Unstable x{unstable_count}, failed "
                    f"checks x{fail_count})."))
            if not causes:
                causes.append(("info",
                    "No issues were detected. Latency, jitter, and packet "
                    "loss are all within normal range."))

        return [{"text": text, "level": level} for level, text in causes]


    def run_troubleshoot(self, device, on_progress=None, on_complete=None, clear_log=False):
        """Dedicated automatic troubleshoot flow.

        Called directly by the monitor when a device becomes Offline.
        This function does NOT run the manual diagnostic sweep and does not
        depend on diagnostic results. It performs the corrective sequence and
        prints only that sequence to this network's dashboard log.
        """
        def _step(msg):
            self.add_auto_troubleshoot_log(msg, device=device)
            if on_progress:
                self.ui.after(0, lambda m=msg: on_progress(m))

        if clear_log:
            with self.lock:
                self.auto_troubleshoot_logs.clear()
            self.ui.after(0, lambda: self.ui.refresh_auto_troubleshoot_log(self))

        def _task():
            ip = device.ip
            system = platform.system().lower()
            is_win = system == "windows"
            is_mac = system == "darwin"
            param = "-n" if is_win else "-c"
            timeout_flag = "-w" if is_win else "-W"

            def probe(label):
                _step(f"{label}...")
                ok = _run(
                    ["ping", param, "2", timeout_flag, "500", ip],
                    capture_output=True,
                ).returncode == 0
                if not ok:
                    for port in (80, 443, 22, 445, 3389):
                        try:
                            with socket.create_connection((ip, port), timeout=0.5):
                                ok = True
                                break
                        except Exception:
                            pass
                _step("Device is responding again!" if ok else "Still no response.")
                return ok

            def exec_fix(label, cmd):
                _step(f"{label}...")
                try:
                    result = _run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        _step(f"{label} completed successfully")
                    else:
                        output = (result.stdout + result.stderr).strip().replace("\n", " ")[:160]
                        _step(f"{label} returned an error: {output or 'operation failed'}")
                except Exception as exc:
                    _step(f"{label} returned an error: {exc}")

            def run_fix_sequence(fixes):
                for label, cmd in fixes:
                    exec_fix(label, cmd)
                    if probe(f"Checking connectivity after {label.lower()}"):
                        return True
                return False

            _step("Device is offline — applying fixes...")
            _step("Cause: device is hard-offline — no response detected. Clearing cached state...")

            if is_win:
                fixes = [
                    ("Flush DNS cache", ["ipconfig", "/flushdns"]),
                    ("Flush ARP cache", ["netsh", "interface", "ip", "delete", "arpcache"]),
                ]
            elif is_mac:
                fixes = [
                    ("Flush DNS cache", ["dscacheutil", "-flushcache"]),
                    ("Reload mDNS responder", ["killall", "-HUP", "mDNSResponder"]),
                    ("Flush ARP cache", ["arp", "-d", "-a"]),
                ]
            else:
                fixes = [
                    ("Flush DNS cache", ["resolvectl", "flush-caches"]),
                    ("Flush ARP cache", ["ip", "neigh", "flush", "all"]),
                ]

            recovered = run_fix_sequence(fixes)
            _step("Device responded — connection restored." if recovered else "Fixes applied but the device still isn't responding.")

            callback = on_complete or (lambda recovered: None)
            self.ui.after(0, lambda r=recovered: callback(r))

        threading.Thread(target=_task, daemon=True).start()


    def add_troubleshoot_log(self, msg):
        """Legacy compatibility hook.

        The old troubleshoot/activity log has been removed. Existing
        non-troubleshoot code may still call this method, but those messages
        are intentionally discarded so they can NEVER appear in the new
        dashboard Troubleshoot Log.
        """
        return


    def add_auto_troubleshoot_log(self, msg, device=None):
        """Append one AUTO-TROUBLESHOOT line to this network's dashboard log.

        Unlike the legacy activity log, this is chronological (oldest at the
        top, newest at the bottom), matching the reference screenshot.

        A device going Offline fires a whole burst of these in quick
        succession (run_troubleshoot's fix sequence), and the list is
        long-lived for the life of the app. Previously every single call
        here triggered a FULL delete+reinsert of the entire log textbox —
        cheap when the log was short, but it only ever grows, so on a
        long-running instance (or a chatty flapping device) that rebuild
        got slower every time, and a burst of them landing within a couple
        seconds around an offline transition is exactly what froze the
        screen. Two changes: (1) cap the log so it can't grow unbounded,
        and (2) push just the ONE new line to the widget instead of
        rebuilding everything, in the common case.
        """
        with self.lock:
            self.auto_troubleshoot_logs.append(f"> {msg}")
            trimmed = len(self.auto_troubleshoot_logs) > 300
            if trimmed:
                self.auto_troubleshoot_logs.pop(0)
        if trimmed:
            # Old lines shifted out of the list — the widget needs a full
            # rebuild to stay in sync. Rare (once every 300th line), and
            # still bounded to 300 lines' worth of work, not unbounded.
            self.ui.after(0, lambda: self.ui.refresh_auto_troubleshoot_log(self))
        else:
            self.ui.after(0, lambda m=msg: self.ui.append_auto_troubleshoot_log_line(self, m))
        # If this line is about a device that belongs to a group, the
        # group's own (independent) Troubleshoot Log gets it too. Done
        # after self.lock is released: the group's log takes the same
        # non-reentrant lock.
        if device is not None:
            group = self._mac_group.get(group_store.normalize_mac(getattr(device, "mac", "")))
            if group is not None:
                group.add_auto_troubleshoot_log(msg)


    def _flush_bandwidth_now(self):
        """Pushes every current device's running _bw_estimated_bytes total
        into bandwidth_store's in-memory cache. This is disk-free and
        fast (see bandwidth_store's module docstring for why) — safe to
        call once per health cycle without this network's monitoring
        loop ever waiting on disk I/O. Only ever touches devices this
        engine currently knows about (self.devices) — a device that's no
        longer part of this network's live dashboard was never in that
        list to begin with, so it can't be saved here or counted in any
        total computed from it."""
        with self.lock:
            totals = {
                d.mac: getattr(d, "_bw_estimated_bytes", 0.0)
                for d in self.devices if d.mac
            }
            network_estimated_total = self._bw_network_estimated_bytes
        bandwidth_store.save_totals(self.network_key, totals)
        bandwidth_store.save_network_estimated_total(
            self.network_key, network_estimated_total
        )
        self._flush_network_real_total_now()

    def _flush_network_real_total_now(self):
        """Persists this session's carried-forward REAL network sent/recv
        totals (previous sessions' saved figure + this session's delta
        so far) to disk, on the same cadence _flush_bandwidth_now already
        uses for the per-device ESTIMATED totals. Without this, the carry
        loaded in _resolve_bandwidth_interface would always be whatever
        was saved as of the LAST time the app happened to close cleanly —
        fine for a normal exit, but a crash or force-kill would lose
        everything accumulated since. Saving periodically here bounds
        that loss to one flush interval, same protection the per-device
        totals already have."""
        if not _PSUTIL_AVAILABLE:
            return
        with self.lock:
            interface = self._bw_interface
            baseline = self._bw_baseline
            carry_sent = self._bw_carry_sent
            carry_recv = self._bw_carry_recv
        if not interface or baseline is None:
            return
        try:
            current = psutil.net_io_counters(pernic=True).get(interface)
            if current is None:
                return
            sent = carry_sent + max(0, current.bytes_sent - baseline.bytes_sent)
            recv = carry_recv + max(0, current.bytes_recv - baseline.bytes_recv)
            bandwidth_store.save_network_real_total(self.network_key, sent, recv)
        except Exception:
            pass

    def _flush_bandwidth_on_exit(self):
        """atexit target: pushes the latest totals into the cache, then
        forces an immediate synchronous disk write instead of waiting for
        bandwidth_store's periodic background writer, which may not get
        another chance to run once the interpreter starts shutting down."""
        self._flush_bandwidth_now()
        bandwidth_store.flush_now()

    def _maybe_flush_bandwidth(self):
        """Periodic autosave for bandwidth totals, called once per health
        cycle — see _BW_FLUSH_INTERVAL_SEC for why this isn't done on
        every cycle instead."""
        now = time.time()
        if now - self._bw_last_flush_ts >= _BW_FLUSH_INTERVAL_SEC:
            self._bw_last_flush_ts = now
            self._flush_bandwidth_now()

    # ---- device groups -------------------------------------------------
    def register_group(self, group):
        self.groups[group.group_id] = group
        self._rebuild_group_maps()

    def unregister_group(self, group_id):
        self.groups.pop(group_id, None)
        self._rebuild_group_maps()

    def _rebuild_group_maps(self):
        """Recomputes the MAC -> group routing map and the set of MACs
        the health loop must skip. A device belongs to at most one group
        (the Manage Groups screen enforces that). Both results are built
        into fresh objects and swapped in, so the health loop never sees
        a half-built set."""
        mac_group = {}
        paused = set()
        for g in list(self.groups.values()):
            members = g.members()
            for mac in members:
                mac_group[mac] = g
            if g.paused:
                paused |= members
        self._mac_group = mac_group
        self.paused_macs = paused

    def stop(self):
        """Stops this network's background monitoring (its loops all
        check self.running) and saves what's still only in memory. Called
        by the UI when a network is removed — previously the UI looked for
        a method like this, found none, and the removed network's threads
        kept probing forever."""
        self.running = False
        for g in list(self.groups.values()):
            try:
                g.stop()
            except Exception:
                pass
        try:
            self._flush_bandwidth_on_exit()
        except Exception:
            pass
        try:
            self._health_pool.shutdown(wait=False)
        except Exception:
            pass

    def clear_history(self):
        """Wipes the status History Log for THIS network only — both the
        in-memory copy every device here is holding right now AND its
        slice of the persisted file on disk. Other monitored networks'
        saved history is untouched."""
        with self.lock:
            for dev in self.devices:
                dev.status_history = []
        history_store.clear_network(self.network_key)


    def clear_bandwidth_totals(self):
        """Resets the running consumption total for every device on THIS
        network, AND the network-wide running total those devices feed
        (see the _bw_network_estimated_bytes field comment in __init__)
        — both the in-memory figures and their saved slice on disk. This
        is the one path that's allowed to bring the network-wide total
        back to zero, since it's an explicit "wipe everything for this
        network" action, unlike clearing a single device. Not wired to
        any button right now (mirrors clear_all in history_store: kept
        available for a possible future "reset bandwidth stats"
        action)."""
        with self.lock:
            for dev in self.devices:
                dev._bw_estimated_bytes = 0.0
            self._bw_network_estimated_bytes = 0.0
        bandwidth_store.clear_network(self.network_key)


    def clear_device_bandwidth(self, mac):
        """Resets the running consumption total for ONE device on this
        network only — both its in-memory figure and its saved slice on
        disk. Every other device (here or on any other monitored
        network) is untouched. This is what the per-device Bandwidth
        popup's CLEAR button calls."""
        if not mac:
            return
        with self.lock:
            dev = next((d for d in self.devices if d.mac == mac), None)
            if dev is not None:
                dev._bw_estimated_bytes = 0.0
        bandwidth_store.clear_device(self.network_key, mac)


    @staticmethod
    def _format_bytes(num_bytes):
        """Human-readable size, e.g. 512.0 KB / 3.42 MB / 1.87 GB."""
        size = float(num_bytes)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024.0:
                return f"{size:.2f} {unit}" if unit != "B" else f"{size:.0f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


    def get_bandwidth_snapshot(self):
        """Bandwidth panel data for this network: a REAL total for this
        HOST's own interface, an ESTIMATED running total across every
        device this network has ever tracked, and an ESTIMATED
        per-device breakdown.

        bytes_total/formatted_total comes straight from the OS's own
        byte counters for the interface this network is on (see
        _resolve_bandwidth_interface), so it reflects every byte that
        actually crossed THIS machine's own interface since this network
        started being monitored — accurate, not a guess, but only ever
        this host's own traffic, not every monitored device's. Available
        only when psutil is installed and that interface could be
        matched; "available" tells the UI which case it's in.

        network_estimated_bytes/formatted_network_estimated_total is what
        the UI's "TOTAL NETWORK CONSUMPTION" panel actually shows: the
        running sum of every device's own ESTIMATED consumption (see the
        per-device section below), kept as its own monotonic counter
        (self._bw_network_estimated_bytes) rather than summed live from
        the devices list, specifically so that clearing one device's own
        total doesn't make this figure drop too.

        The per-device numbers can NOT be real the same way: a normal
        client machine on a switched network or Wi-Fi simply cannot see
        another device's individual traffic without router-side support
        (SNMP) that this app doesn't integrate with, and this app
        intentionally does not intercept other devices' traffic to fake
        that visibility (see the accumulation comment in monitor_network).
        Each device's figure here is instead built by integrating its own
        periodic speed-probe reading over real elapsed time — a
        reasonable approximation, never a metered count. The UI is
        expected to label this column "Estimated", not "Total", to keep
        that distinction visible to the user.
        """
        with self.lock:
            interface = self._bw_interface
            baseline = self._bw_baseline
            session_start = self._bw_session_start
            carry_sent = self._bw_carry_sent
            carry_recv = self._bw_carry_recv
            network_estimated_bytes = self._bw_network_estimated_bytes
            devices_snapshot = [
                (d.name, d.ip, d.mac, d.status, getattr(d, "_bw_estimated_bytes", 0.0))
                for d in self.devices
            ]

        result = {
            "network_total_available": False,
            "interface": interface,
            "since": session_start.strftime("%Y-%m-%d %H:%M:%S"),
            "bytes_sent": 0,
            "bytes_recv": 0,
            "bytes_total": 0,
            "formatted_total": "--",
            "formatted_sent": "--",
            "formatted_recv": "--",
            # Live sum of every CURRENTLY-tracked device's own ESTIMATED
            # figure, recomputed fresh on every call. This shrinks the
            # instant any one device's total is cleared (clearing zeroes
            # that device's own bucket, and this sum simply adds up
            # whatever's there right now) — useful if that live-sum
            # behavior is ever wanted again, but NOT what the "TOTAL
            # NETWORK CONSUMPTION" panel uses; see
            # network_estimated_bytes/formatted_network_estimated_total
            # below for that.
            "estimated_total_bytes": 0.0,
            "formatted_estimated_total": "--",
            # The network-wide running ESTIMATED total: what "TOTAL
            # NETWORK CONSUMPTION" in the UI actually shows. Unlike
            # estimated_total_bytes above, this is NOT a live sum of the
            # devices list — it's engine._bw_network_estimated_bytes, a
            # separate monotonic counter that only ever grows (see its
            # field comment in __init__), so clearing one device's own
            # total does not make this figure drop. Still an estimate,
            # not a metered count, since it's built from the same
            # per-device speed-probe integration as every device's own
            # figure — never present it as "real" in the UI.
            "network_estimated_bytes": network_estimated_bytes,
            "formatted_network_estimated_total": self._format_bytes(network_estimated_bytes),
            "devices": [],
        }

        if _PSUTIL_AVAILABLE and interface and baseline is not None:
            try:
                current = psutil.net_io_counters(pernic=True).get(interface)
                if current is not None:
                    # Carry-over (earlier sessions) + this session's own
                    # delta since its baseline — see the carry_sent/recv
                    # comment above for why, and _flush_network_real_total
                    # for where the carry itself gets saved back to disk.
                    sent = carry_sent + max(0, current.bytes_sent - baseline.bytes_sent)
                    recv = carry_recv + max(0, current.bytes_recv - baseline.bytes_recv)
                    result["network_total_available"] = True
                    result["bytes_sent"] = sent
                    result["bytes_recv"] = recv
                    result["bytes_total"] = sent + recv
                    result["formatted_total"] = self._format_bytes(sent + recv)
                    result["formatted_sent"] = self._format_bytes(sent)
                    result["formatted_recv"] = self._format_bytes(recv)
            except Exception:
                pass

        devices_snapshot.sort(key=lambda row: row[4], reverse=True)
        result["devices"] = [
            {
                "name": name, "ip": ip, "mac": mac, "status": status,
                "estimated_bytes": est,
                "formatted_estimate": self._format_bytes(est),
            }
            for name, ip, mac, status, est in devices_snapshot
        ]

        # The host machine (the one running this app) is deliberately NOT
        # in self.devices — discovery skips host_ip — so it never gets a
        # probe-based estimate and wouldn't appear in this list at all.
        # But unlike every other device, its traffic IS measurable: it's
        # the interface byte counter already read above. When that real
        # total is available, add the host as its own row using the REAL
        # bytes (sent + recv) instead of an estimate, so a download done
        # on this machine shows up here and ranks accordingly. The row is
        # flagged is_host/is_real so the UI can label it "Actual" rather
        # than "Estimated". It is added AFTER the sort-source rows and is
        # not included in estimated_total_bytes below, so nothing is
        # double-counted in the estimated network figures.
        if result["network_total_available"] and self.host_ip:
            try:
                host_mac = ""
                try:
                    for addr in psutil.net_if_addrs().get(interface, []):
                        if addr.family == getattr(psutil, "AF_LINK", None):
                            host_mac = addr.address.replace("-", ":").lower()
                            break
                except Exception:
                    pass
                host_bytes = float(result["bytes_total"])
                result["devices"].append({
                    "name": f"{socket.gethostname()} (This device)",
                    "ip": self.host_ip, "mac": host_mac, "status": "Online",
                    "estimated_bytes": host_bytes,
                    "formatted_estimate": self._format_bytes(host_bytes),
                    "is_host": True,
                    "is_real": True,
                })
                result["devices"].sort(key=lambda r: r["estimated_bytes"], reverse=True)
            except Exception:
                pass

        estimated_total = sum(row[4] for row in devices_snapshot)
        result["estimated_total_bytes"] = estimated_total
        result["formatted_estimated_total"] = (
            self._format_bytes(estimated_total) if devices_snapshot else "--"
        )
        return result

    def get_device_bandwidth_history(self, mac):
        """Rolling per-interval consumption samples for one device, for
        the Bandwidth popup's graph (see the _bw_rate_history comment in
        update_health for why this is per-interval usage rather than the
        running cumulative total). Returns a list of
        (unix_timestamp, bytes_used_that_interval) tuples, oldest first,
        capped at the last 60 samples (~2 minutes at this app's 2s health
        loop cadence). `bytes_used_that_interval` is 0.0 for a confirmed-
        zero interval (device unreachable that cycle) or None for a
        cycle where the device WAS responding but no usable speed reading
        came back — the caller should treat those two differently rather
        than plotting both as zero. Empty list if the device isn't found
        or has no samples yet."""
        with self.lock:
            dev = next((d for d in self.devices if d.mac == mac), None)
            if dev is None:
                return []
            hist = getattr(dev, "_bw_rate_history", None)
            if not hist:
                return []
            return list(hist)


    def proactive_scan(self):
        """Full-/24 'wake up' sweep run once when this network starts
        monitoring. Both the ping sweep and the TCP-probe fallback are
        routed through the module-level _PROACTIVE_SCAN_POOL (see its
        comment) rather than spawning their own unbounded subprocesses/
        threads — that pool is shared by every monitored network, so no
        matter how many networks start together, the total number of
        pings/probes actually running at once across all of them stays
        capped at the pool's worker count instead of stacking on top of
        each other."""
        self.add_troubleshoot_log("STARTING FAST-SCAN WAKEUP...")
        is_win = platform.system().lower() == "windows"
        param = "-n" if is_win else "-c"
        timeout_flag = "-w" if is_win else "-W"


        def ping_once(target):
            try:
                _run(
                    ["ping", param, "1", timeout_flag, "300", target],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass


        # Submitting (rather than starting a raw thread/process per IP)
        # means anything beyond the pool's 40 workers simply queues —
        # this network's own sweep, and every other network's sweep
        # running at the same moment, all draw from the same bounded
        # pot of concurrency instead of each getting its own unbounded
        # burst. timeout is a safety ceiling, not the expected runtime:
        # a full /24 through 40 workers normally finishes in a few
        # seconds even with several networks sharing the pool.
        futures = [
            _PROACTIVE_SCAN_POOL.submit(ping_once, f"{self.base_ip}.{i}")
            for i in range(1, 255)
        ]
        concurrent.futures.wait(futures, timeout=30)


        def tcp_probe(ip):
            for port in [80, 443, 22, 8080, 445]:
                try:
                    with socket.create_connection((ip, port), timeout=0.5):
                        _run(
                            ["ping", param, "1", timeout_flag, "100", ip],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                        )
                        return
                except Exception:
                    pass


        tcp_futures = [
            _PROACTIVE_SCAN_POOL.submit(tcp_probe, f"{self.base_ip}.{i}")
            for i in range(1, 255)
            if not any(dev.ip == f"{self.base_ip}.{i}" for dev in self.devices)
        ]
        concurrent.futures.wait(tcp_futures, timeout=15)


        self.add_troubleshoot_log("NETWORK AWAKENED. SYNCHRONIZING DASHBOARD...")


    @staticmethod
    def detect_networks():
        """Auto-detect all network interfaces. Returns list of base_ips."""
        networks = []
        is_win = platform.system().lower() == "windows"
        is_mac = platform.system().lower() == "darwin"


        def _add(ip):
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                return
            base = ".".join(ip.split(".")[:3])
            if base not in networks:
                networks.append(base)


        # Windows: ipconfig
        if is_win:
            try:
                result = _run(["ipconfig"], capture_output=True, text=True,
                              encoding="cp1252", errors="replace")
                for line in result.stdout.splitlines():
                    m = re.search(r"IPv4.*?:\s*((\d+\.){3}\d+)", line)
                    if m:
                        _add(m.group(1))
            except Exception:
                pass


        # macOS: ipconfig getifaddr per interface
        if is_mac:
            for iface in ("en0", "en1", "en2", "en3", "utun0", "bridge0"):
                try:
                    r = _run(["ipconfig", "getifaddr", iface],
                             capture_output=True, text=True, timeout=2)
                    _add(r.stdout.strip())
                except Exception:
                    pass


        # Linux: ip addr show
        if not is_win and not is_mac:
            try:
                r = _run(["ip", "addr", "show"], capture_output=True, text=True)
                for line in r.stdout.splitlines():
                    m = re.search(r"inet\s+((\d+\.){3}\d+)", line)
                    if m:
                        _add(m.group(1))
            except Exception:
                pass


        # Universal fallback: socket trick
        if not networks:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                _add(s.getsockname()[0])
                s.close()
            except Exception:
                pass


        return networks[:5]