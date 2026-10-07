"""
Persistent storage for the device status history log.

Everything the engine tracks in-memory (device.status_history) previously
lived only in RAM, so it vanished the moment the app closed. This module
mirrors those entries out to a small JSON file in the OS's standard
per-user "app data" folder — a location that lives OUTSIDE wherever the
app itself is installed/unpacked to. That distinction is what makes it
survive:

  - Closing the app:            file is untouched either way.
  - Deleting/reinstalling the app (dragging the .exe/.app to Trash,
    unzipping a new build, running a fresh installer over the old one):
    the app's own folder is wiped, but this file lives elsewhere, so a
    later install of the same app on the same machine will find it again.

It does NOT survive the user manually deleting that app-data folder, or a
"clean uninstall" tool that specifically targets it — same as any other
app's saved settings/history.

Layout on disk:
    Windows:  %APPDATA%\\NetHealer\\history_log.json
    macOS:    ~/Library/Application Support/NetHealer/history_log.json
    Linux:    $XDG_DATA_HOME/NetHealer/history_log.json
              (or ~/.local/share/NetHealer/history_log.json)

File format: {"<network base_ip, e.g. 192.168.0>": {"<mac address>":
              [ {ts, status, latency, jitter, packet_loss, network_speed,
              ip, name}, ... ], ...}, ...}

Scoped two levels deep — network first, then MAC — so that:
  - Two different networks you monitor (home, office, a client site)
    never mix histories, and "Clear History" on one doesn't touch another.
  - Within a network, history still follows a device by MAC rather than
    IP, since DHCP can hand a device a new IP between sessions but its
    MAC stays put.

WHY AN IN-MEMORY CACHE + BACKGROUND WRITER:
append_entry() used to do a full disk read-modify-write on every single
call. That's fine for the occasional status change, but a device (or
several devices at once, e.g. a flaky access point) can flap between
Online/Unstable/Offline in quick bursts, each flap logging a new entry —
and on a busier network, several monitored networks' engines can all be
logging around the same moment. Doing a real disk read+write for every
one of those, back to back, was a genuine source of stutter, the same
issue bandwidth_store.py had for a different reason (see its module
docstring).

The fix is the same shape here: append_entry() only ever touches an
in-memory dict and returns immediately — no disk access on that path. A
single shared background thread wakes up periodically and writes that
in-memory state to disk ONLY if something actually changed since the
last write, so a whole burst of flaps between two writes still costs
just one disk write, not one per flap. flush_now() forces an immediate
synchronous write for app shutdown, since a daemon thread can be killed
mid-sleep before it gets a chance to run on its own.
"""

import json
import os
import platform
import threading
import time

_APP_NAME = "NetHealer"
_MAX_ENTRIES_PER_DEVICE = 500  # generous cap on disk; the UI only ever shows the most recent slice

# Where entries land if they were saved by an older version of this file
# that had no concept of "network" yet (flat {mac: [entries]} format).
# Kept around read-only so upgrading never silently deletes anyone's past
# history — see _migrate_and_clean()'s migration step below.
_LEGACY_BUCKET = "_unscoped_legacy"

# How often the background writer checks whether there's anything new to
# save. Independent from how often append_entry() gets called — that can
# happen many times in a burst; this just caps how often that burst
# actually touches disk.
_WRITE_INTERVAL_SEC = 5

_lock = threading.Lock()
_dir_cache = None
_cache = None             # lazily loaded from disk, then kept in memory
_dirty = False             # True when _cache has changes not yet on disk
_writer_started = False


def get_persistent_dir():
    """The stable, per-user data folder that lives outside the app's own
    install/unpack location. Created on first use if it doesn't exist."""
    global _dir_cache
    if _dir_cache:
        return _dir_cache

    system = platform.system().lower()
    if system == "windows":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif system == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

    path = os.path.join(base, _APP_NAME)
    try:
        os.makedirs(path, exist_ok=True)
    except Exception:
        # Fall back to the user's home directory if the standard location
        # is somehow unwritable, so history-saving degrades instead of crashing.
        path = os.path.join(os.path.expanduser("~"), f".{_APP_NAME.lower()}")
        os.makedirs(path, exist_ok=True)

    _dir_cache = path
    return path


def _history_file():
    return os.path.join(get_persistent_dir(), "history_log.json")


def _load_from_disk():
    path = _history_file()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        # Corrupt/partial file (e.g. app killed mid-write) — don't crash the
        # app over a broken log, just start fresh from here on.
        return {}


def _migrate_and_clean(data):
    """One-time shape fixes applied right after loading from disk.
    Returns (data, changed) — `changed` tells the caller whether the
    result needs to be written back at some point.

    1) The very first version of this file was flat, {mac: [entries...]},
       with no per-network scoping at all. Detect that shape (every
       top-level value is a list rather than a dict-of-lists) and fold it
       under _LEGACY_BUCKET instead of discarding it, so upgrading to
       network-scoped history doesn't wipe out what was already saved.
    2) Drop any bucket saved under a broadcast/null MAC — these were
       never real devices, just a stale artifact from before
       discover_devices() filtered them out at the source.
    """
    if data and all(isinstance(v, list) for v in data.values()):
        return {_LEGACY_BUCKET: data}, True

    junk_macs = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
    changed = False
    for net_bucket in list(data.values()):
        if not isinstance(net_bucket, dict):
            continue
        for junk in junk_macs:
            if junk in net_bucket:
                del net_bucket[junk]
                changed = True
    return data, changed


def _load_cache_locked():
    """Populates the module-level cache from disk on first use (applying
    the one-time migration/cleanup above). Must be called with `_lock`
    already held."""
    global _cache, _dirty
    if _cache is not None:
        return _cache
    data, changed = _migrate_and_clean(_load_from_disk())
    _cache = data
    if changed:
        _dirty = True
    return _cache


def _write_cache_locked():
    """Writes the current in-memory cache to disk. Must be called with
    `_lock` already held."""
    if _cache is None:
        return
    path = _history_file()
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
    """Returns the saved history list for one device on one network
    (empty if none yet). Falls back to pre-migration legacy entries for
    that MAC if the network-scoped bucket has nothing, so devices don't
    appear to have lost their history right after upgrading."""
    if not mac or not network_key:
        return []
    with _lock:
        data = _load_cache_locked()
        entries = list(data.get(network_key, {}).get(mac, []))
        if not entries:
            entries = list(data.get(_LEGACY_BUCKET, {}).get(mac, []))
        return entries


def append_entry(network_key, mac, ip, name, entry):
    """Records one new status-change entry in the in-memory cache
    immediately (disk-free and fast — see the module docstring for why).
    `entry` is the same dict the engine already builds for
    device.status_history; ip/name are stamped on for context since MAC
    alone isn't human-readable in the log file. The actual save to disk
    happens separately and periodically, via the background writer
    started by _ensure_writer_thread()."""
    global _dirty
    if not mac or not network_key:
        return
    _ensure_writer_thread()
    with _lock:
        data = _load_cache_locked()
        net_bucket = data.setdefault(network_key, {})
        dev_bucket = net_bucket.setdefault(mac, [])
        record = dict(entry)
        record["ip"] = ip
        record["name"] = name
        dev_bucket.append(record)
        if len(dev_bucket) > _MAX_ENTRIES_PER_DEVICE:
            del dev_bucket[: len(dev_bucket) - _MAX_ENTRIES_PER_DEVICE]
        _dirty = True


def clear_network(network_key):
    """Wipes only the saved history for one network (e.g. the one you're
    currently looking at), leaving every other monitored network's saved
    history untouched. Writes to disk immediately — this only runs on an
    explicit user action (the CLEAR HISTORY button), not on the frequent
    per-entry path, so there's no lag concern here."""
    global _dirty
    if not network_key:
        return
    with _lock:
        data = _load_cache_locked()
        if network_key in data:
            del data[network_key]
            _write_cache_locked()
            _dirty = False


def clear_all():
    """Wipes the saved history file entirely — every network, every
    device. Not wired to any button right now (clear_network is what
    "CLEAR HISTORY" uses); kept available for a possible future
    "reset everything" action."""
    global _cache, _dirty
    with _lock:
        _cache = {}
        _dirty = False
        path = _history_file()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass


def flush_now():
    """Forces an immediate synchronous write of whatever's currently in
    memory, bypassing the periodic writer thread. Meant for app shutdown
    (see engine.py's atexit hook) — a daemon thread can be killed
    mid-sleep before it ever gets a chance to run, so exit is the one
    path that can't rely on it."""
    global _dirty
    with _lock:
        if _cache is not None:
            _write_cache_locked()
        _dirty = False