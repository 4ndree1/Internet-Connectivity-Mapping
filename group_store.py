"""
Persistent storage for manually-assigned DEVICE GROUPS.

A group is a hand-picked set of devices (by MAC) that belong to ONE
monitored network. Each group gets its own dashboard in the UI (see
group_engine.GroupEngine), independent of the network dashboard it was
carved out of.

Lives in the same per-user app-data folder as history_store.py /
bandwidth_store.py, in "device_groups.json", so groups survive closing or
reinstalling the app.

Scoped by network_key first (the same key history_store and
bandwidth_store use), so two different physical networks never share
groups, even if both are 192.168.1.x.

Group edits are explicit user actions (Manage Groups -> Save, rename,
delete), so — unlike the per-cycle bandwidth totals — a direct atomic
disk write here is fine.

File format:
    {"<network_key>": {"<group_id>": {"id": "<group_id>",
                                      "name": "<display name>",
                                      "macs": ["aa:bb:...", ...],
                                      "created": "<iso ts>",
                                      "history_cleared_at": "<ts or null>"},
                       ...}, ...}
"""

import json
import os
import threading
import uuid
from datetime import datetime

import history_store

_FILE_NAME = "device_groups.json"
MAX_NAME_LEN = 24

_lock = threading.Lock()


def _path():
    return os.path.join(history_store.get_persistent_dir(), _FILE_NAME)


def _load():
    path = _path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data):
    path = _path()
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        pass


def new_group_id():
    return uuid.uuid4().hex[:12]


def normalize_mac(mac):
    return (mac or "").strip().lower().replace("-", ":")


def load_groups(network_key, base_ip=None):
    """Returns the saved group records (a list of dicts) for one network.

    network_key can change shape while an engine starts up (base_ip alone
    at first, then "base_ip::gateway_mac" once the gateway answers ARP).
    If nothing is saved under the current key but something is saved
    under the bare base_ip, those records are moved to the current key so
    groups don't appear to vanish when the key gets more specific."""
    if not network_key:
        return []
    with _lock:
        data = _load()
        groups = data.get(network_key)
        if not groups and base_ip and base_ip != network_key:
            legacy = data.get(base_ip)
            if legacy:
                data[network_key] = legacy
                del data[base_ip]
                _save(data)
                groups = legacy
        if not isinstance(groups, dict):
            return []
        return [dict(rec) for rec in groups.values() if isinstance(rec, dict)]


def save_group(network_key, record):
    """Creates or replaces one group record (matched by record['id'])."""
    if not network_key or not record or not record.get("id"):
        return
    rec = dict(record)
    rec["macs"] = sorted({normalize_mac(m) for m in rec.get("macs", []) if m})
    rec.setdefault("created", datetime.now().isoformat(timespec="seconds"))
    with _lock:
        data = _load()
        data.setdefault(network_key, {})[rec["id"]] = rec
        _save(data)


def delete_group(network_key, group_id):
    if not network_key or not group_id:
        return
    with _lock:
        data = _load()
        bucket = data.get(network_key)
        if bucket and group_id in bucket:
            del bucket[group_id]
            if not bucket:
                del data[network_key]
            _save(data)