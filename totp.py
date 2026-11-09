"""Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 s) with replay protection,
plus single-use recovery codes. Standard, works with Google Authenticator, Authy, 1Password, etc."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1  # accept the previous and next 30 s slot (clock drift)


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    num = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(num).zfill(DIGITS)


def code_now(secret: str, at: float | None = None) -> str:
    return _code(secret, int((time.time() if at is None else at) // STEP))


def verify(secret: str, code: str, last_step: int = 0, at: float | None = None) -> int | None:
    """Return the matched time step if the code is valid AND newer than last_step, else None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS:
        return None
    now_step = int((time.time() if at is None else at) // STEP)
    found = None
    for delta in range(-WINDOW, WINDOW + 1):  # no early exit: constant work
        step = now_step + delta
        if hmac.compare_digest(_code(secret, step), code) and step > last_step:
            found = step if found is None else max(found, step)
    return found


def uri(email: str, secret: str, issuer: str) -> str:
    label = quote(f"{issuer}:{email}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


def format_secret(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def new_recovery_codes(n: int = 8) -> list[str]:
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(5)) + "-" + "".join(secrets.choice(alphabet) for _ in range(5))
            for _ in range(n)]


def normalize_recovery(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())
