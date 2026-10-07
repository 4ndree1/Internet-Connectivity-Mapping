"""
Local account storage for the NetHealer login / registration page.

Accounts live in the same per-user app-data folder as history_store.py and
bandwidth_store.py (so they survive closing/reinstalling the app), in
"auth_users.json".

Passwords are NEVER stored in plain text. Each account keeps a random
per-user salt plus a PBKDF2-HMAC-SHA256 hash of the password.

This is a local, on-device gate — there is no server. It keeps casual
users out of the dashboard, but anyone with access to the machine's
files can delete auth_users.json. That's the normal limit of any
offline app login.

Registration is FIRST-RUN ONLY: register() succeeds only while no account
exists yet, and that first account is the one and only account. After that
registration is closed — see register() below.

Login history (who logged in, and when) is kept separately in
"login_history.json" — see record_event()/get_login_history() below.

File format of auth_users.json:
    {"<username, lowercased>": {"display": "<username as typed>",
                                "salt": "<hex>", "hash": "<hex>",
                                "iterations": <int>, "created": "<iso ts>"}, ...}
"""

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime

import history_store

_FILE_NAME = "auth_users.json"
_LOG_FILE_NAME = "login_history.json"
_MAX_LOG_ENTRIES = 1000
_ITERATIONS = 200_000
MIN_PASSWORD_LEN = 8
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

_lock = threading.Lock()


def _users_file():
    return os.path.join(history_store.get_persistent_dir(), _FILE_NAME)


def _load():
    path = _users_file()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data):
    path = _users_file()
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)


def _hash(password, salt, iterations):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    ).hex()


def has_any_users():
    with _lock:
        return bool(_load())


def validate_registration(username, password, confirm):
    """Returns an error message string, or None if the input is valid."""
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, numbers, . _ -"
    if len(password or "") < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if password != confirm:
        return "Passwords do not match."
    return None


REGISTRATION_CLOSED_MSG = "Registration is closed. An account already exists on this device."


def register(username, password, confirm):
    """Creates the first (and only) account. Returns (ok, message).
    Refused once any account exists, so nobody else can sign themselves up."""
    if has_any_users():
        return False, REGISTRATION_CLOSED_MSG
    err = validate_registration(username, password, confirm)
    if err:
        return False, err
    username = username.strip()
    key = username.lower()
    with _lock:
        data = _load()
        if data:
            # Re-checked inside the lock so two racing calls can't both pass.
            return False, REGISTRATION_CLOSED_MSG
        if key in data:
            return False, "That username is already taken."
        salt = secrets.token_bytes(16)
        data[key] = {
            "display": username,
            "salt": salt.hex(),
            "hash": _hash(password, salt, _ITERATIONS),
            "iterations": _ITERATIONS,
            "created": datetime.now().isoformat(timespec="seconds"),
        }
        try:
            _save(data)
        except Exception:
            return False, "Could not save the account (disk error)."
    record_event(username, "REGISTERED")
    return True, "Account created."


def verify(username, password):
    """Checks credentials. Returns the display username on success, else None.
    Does the same amount of hashing work whether or not the user exists, so
    response time doesn't reveal which usernames are registered."""
    key = (username or "").strip().lower()
    with _lock:
        rec = _load().get(key)
    if not rec:
        _hash(password or "", b"\x00" * 16, _ITERATIONS)
        record_event(username, "FAILED")
        return None
    try:
        salt = bytes.fromhex(rec["salt"])
        expected = rec["hash"]
        actual = _hash(password or "", salt, int(rec.get("iterations", _ITERATIONS)))
    except Exception:
        return None
    if hmac.compare_digest(actual, expected):
        display = rec.get("display", key)
        record_event(display, "LOGIN")
        return display
    record_event(rec.get("display", key), "FAILED")
    return None


# ---- login history -----------------------------------------------------
def _log_file():
    return os.path.join(history_store.get_persistent_dir(), _LOG_FILE_NAME)


def _load_log():
    path = _log_file()
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def record_event(username, event):
    """Appends one entry to the login history. event is one of
    "LOGIN", "REGISTERED" or "FAILED". Logins are rare user actions, so a
    direct disk write here is fine (no background writer needed)."""
    entry = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "username": (username or "").strip()[:64] or "(blank)",
        "event": event,
    }
    with _lock:
        log = _load_log()
        log.append(entry)
        if len(log) > _MAX_LOG_ENTRIES:
            del log[: len(log) - _MAX_LOG_ENTRIES]
        try:
            path = _log_file()
            tmp_path = path + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(log, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            pass


def get_login_history(limit=500):
    """Returns the most recent entries, newest first."""
    with _lock:
        log = _load_log()
    return list(reversed(log[-limit:]))