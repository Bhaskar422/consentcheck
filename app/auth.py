"""Admin authentication: one admin account, signed session cookie, login throttling.

The password comes from CC_ADMIN_PASSWORD. If it is not set, a random one is
generated on first start and written to <runs>/.admin_password (mode 600), so a
fresh install is never left with a default password.
"""

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import HTTPException, Request

COOKIE = "cc_admin"
SESSION_TTL = 12 * 3600
MAX_FAILURES = 5
FAILURE_WINDOW = 300

ADMIN_USER = os.environ.get("CC_ADMIN_USER", "admin")
_SECRET = (os.environ.get("CC_SESSION_SECRET") or secrets.token_hex(32)).encode()
_failures: dict[str, list[float]] = {}
_password: str | None = None


def init(runs_dir: Path) -> str:
    """Load or create the admin password. Returns where it came from (for the log)."""
    global _password
    env = os.environ.get("CC_ADMIN_PASSWORD", "").strip()
    if env:
        _password = env
        return "from CC_ADMIN_PASSWORD"
    f = runs_dir / ".admin_password"
    if f.is_file() and f.read_text().strip():
        _password = f.read_text().strip()
    else:
        runs_dir.mkdir(parents=True, exist_ok=True)
        _password = secrets.token_urlsafe(12)
        f.write_text(_password + "\n")
        f.chmod(0o600)
    return f"generated, stored in {f}"


def _sign(payload: str) -> str:
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def make_session(user: str) -> str:
    payload = f"{user}|{int(time.time()) + SESSION_TTL}"
    return f"{payload}|{_sign(payload)}"


def session_user(request: Request) -> str | None:
    raw = request.cookies.get(COOKIE, "")
    parts = raw.split("|")
    if len(parts) != 3:
        return None
    user, exp, sig = parts
    if not hmac.compare_digest(sig, _sign(f"{user}|{exp}")):
        return None
    if not exp.isdigit() or int(exp) < time.time():
        return None
    return user


def require_admin(request: Request) -> str:
    user = session_user(request)
    if not user:
        raise HTTPException(401, "Admin login required.")
    return user


def check_login(ip: str, user: str, password: str) -> bool:
    now = time.time()
    if len(_failures) > 10000:  # forget stale entries so the table cannot grow without bound
        for k in [k for k, v in _failures.items() if not v or now - v[-1] > FAILURE_WINDOW]:
            _failures.pop(k, None)
    recent = [t for t in _failures.get(ip, []) if now - t < FAILURE_WINDOW]
    _failures[ip] = recent
    if len(recent) >= MAX_FAILURES:
        raise HTTPException(429, {"message": "Too many failed logins. Wait five minutes.",
                                  "retry_at": int(recent[0] + FAILURE_WINDOW)})
    ok = _password is not None and hmac.compare_digest(user.encode(), ADMIN_USER.encode()) \
        and hmac.compare_digest(password.encode(), _password.encode())
    if not ok:
        recent.append(now)
        if len(recent) >= MAX_FAILURES:
            raise HTTPException(429, {"message": "Too many failed logins. Wait five minutes.",
                                      "retry_at": int(recent[0] + FAILURE_WINDOW)})
        raise HTTPException(401, {"message": "Wrong username or password.",
                                  "attempts_left": MAX_FAILURES - len(recent)})
    _failures.pop(ip, None)
    return ok
