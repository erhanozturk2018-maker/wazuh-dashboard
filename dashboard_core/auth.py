"""
User accounts and session handling.

Passwords are hashed with PBKDF2 (no external dependency) and sessions are
signed, timestamped cookies - there is no server-side session store, so logout
is a cookie delete (docs/security/dashboard-side.md).
"""

import base64
import hashlib
import hmac
import secrets
import time
from datetime import datetime

from fastapi import Request

from dashboard_core import config
from dashboard_core.storage import load_users, save_json


def get_secret_key() -> bytes:
    """Random key used to sign session cookies. Generated on first run and
    written to data/secret.key, then read from there on every subsequent
    run (otherwise every restart would invalidate all active sessions)."""
    if config.SECRET_FILE.exists():
        return bytes.fromhex(config.SECRET_FILE.read_text().strip())
    key_hex = secrets.token_hex(32)
    config.SECRET_FILE.write_text(key_hex)
    return bytes.fromhex(key_hex)


SECRET_KEY = get_secret_key()


# ---- Password hashing (PBKDF2, no external dependency needed) ----
def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, digest_hex = hash_password(password, salt)
    return hmac.compare_digest(digest_hex, hash_hex)


def create_user(username: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    if not username or not password:
        return False, "Username and password cannot be empty."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    users = load_users()
    if any(u.lower() == username.lower() for u in users):
        return False, "This username is already taken."

    salt_hex, hash_hex = hash_password(password)
    users[username] = {
        "salt": salt_hex,
        "hash": hash_hex,
        "created": datetime.now().isoformat(),
    }
    save_json(config.USERS_FILE, users)
    return True, "Registration successful, you can log in now."


def authenticate(username: str, password: str) -> bool:
    users = load_users()
    user = users.get(username)
    if not user:
        return False
    return verify_password(password, user["salt"], user["hash"])


# ---- Session - simple signed, timestamped token ----
def make_session_token(username: str) -> str:
    expiry = int(time.time()) + config.SESSION_MAX_AGE
    payload = f"{username}:{expiry}"
    sig = hmac.new(SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("utf-8")


def verify_session_token(token: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        username, expiry, sig = raw.rsplit(":", 2)
        expected = hmac.new(SECRET_KEY, f"{username}:{expiry}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(expiry) < time.time():
            return None
        return username
    except Exception:
        return None


def get_current_user(request: Request) -> str | None:
    token = request.cookies.get(config.SESSION_COOKIE)
    if not token:
        return None
    return verify_session_token(token)
