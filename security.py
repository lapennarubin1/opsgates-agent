"""Allowed paths, secret redaction, limits and the common decorator every tool goes through."""
from __future__ import annotations

import collections
import fnmatch
import functools
import inspect
import re
import threading
import time
from pathlib import Path
from typing import Callable

import anyio

import audit
from config import cfg

# ---------------------------------------------------------------- redaction
_PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_URLCRED = re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@]+):[^\s@/]+@")
# Names that mark a secret value (case-insensitive, anywhere in the key: DB_PASSWORD, smtp_pass...).
_SECRET_NAME = (r"[\w.-]*(?:password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|auth[_-]?key"
                r"|private[_-]?key|access[_-]?key|credential|md5_cred|requirepass|masterauth|logged_in_key"
                r"|nonce_key|salt|(?<![A-Za-z])pass(?![A-Za-z])|(?<![A-Za-z])auth(?![A-Za-z]))[\w.-]*")
_VALUE = r"""(?:"[^"\n]*"|'[^'\n]*'|[^\s,;)]+)"""
# key = value · key: value · 'key' => 'value' (PHP arrays)
_KV = re.compile(r"""(?i)(["']?""" + _SECRET_NAME + r"""["']?\s*(?:=>|=|:(?!\d+:))\s*)""" + _VALUE)
# define('DB_PASSWORD', 'value') (PHP/WordPress) · ('password', 'value') tuples
_KV_CALL = re.compile(r"""(?i)(["']""" + _SECRET_NAME + r"""["']\s*,\s*)(?:"[^"\n]*"|'[^'\n]*')""")
# Config-file lines "key value" (nginx, redis requirepass, ...), also after a line-number or
# grep "file:line:" prefix. Only when the value ends the line (or ; / #), so prose is left alone.
_KV_LINE = re.compile(r"""(?im)^((?:[ \t]*\d+\t|[^\s:]+:\d+:|[^\s:]+:)?[ \t]*""" + _SECRET_NAME
                      + r"""[ \t]+)(?![=:])(?:"[^"\n]*"|'[^'\n]*'|[^\s;#]+)(?=[ \t]*(?:;|#|$))""")

# .netrc: "machine h login bob password X" (also "account")
_NETRC = re.compile(r"(?i)(\b(?:login|account)[ \t]+\S+[ \t]+password[ \t]+)\S+")
# XML elements: <password>X</password>, <DbPassword>X</DbPassword>
_XML = re.compile(r"(?i)(<(?P<tag>[\w:.-]*(?:password|passwd|pwd|secret|token|apikey|api_key|credential)[\w:.-]*)"
                  r"(?:\s[^>]*)?>)[^<]+(?=</(?P=tag)\s*>)")
# .NET / Java config: <add key="DbPassword" value="X"/>, name="token" value="X"
_KEY_VALUE_ATTR = re.compile(r"""(?i)(\b(?:key|name)\s*=\s*["']""" + _SECRET_NAME
                             + r"""["']\s+value\s*=\s*)(?:"[^"]*"|'[^']*')""")
# mysql / mysqldump -pSECRET (password glued to -p)
_MYSQL_P = re.compile(r"""(?im)(\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mariadb|mariadb-dump)\b"""
                      r"""[^\n]*?[ \t]-p)(?:'[^'\n]*'|"[^"\n]*"|[^\s'"]+)""")
# .pgpass: host:port:database:user:password
_PGPASS = re.compile(r"(?m)^((?:[ \t]*\d+\t|[^\s:]+:\d+:[ \t]*|\d+:)?[^:\s]+:(?:\d+|\*):[^:\s]+:[^:\s]+:)[^\s:]+[ \t]*$")
# Authorization: Token X / Digest X / any scheme
_AUTHZ = re.compile(r"""(?i)(\bauthorization["']?\s*[:=]\s*["']?[A-Za-z-]+[ \t]+)[^\s"',;]+""")
# curl -u user:X / --user user:X / wget --password X handled by _KV_LINE-like rules
_CURL_U = re.compile(r"""(?i)((?<!\S)(?:-u|--user|--proxy-user)[ \t=]+["']?[^:\s"']+:)[^\s"']+""")

# Command-line secrets: --password X / --token X (space separated), redis-cli -a X, sshpass -p X,
# docker/podman login -p X
_CLI_LONG = re.compile(r"""(?i)((?<!\S)--(?:password|passwd|pass|token|secret|api-key|apikey|auth|auth-token)[ \t]+)"""
                       r"""(?:'[^'\n]*'|"[^"\n]*"|[^\s'"]+)""")
_CLI_SHORT = re.compile(r"""(?im)(\b(?:redis-cli|sshpass|docker|podman|nerdctl)\b[^\n]*?(?<!\S)-[ap][ \t]+)"""
                        r"""(?:'[^'\n]*'|"[^"\n]*"|[^\s'"]+)""")
# YAML block scalars: "password: |" with the secret on the following indented lines
_LINE_PREFIX = r"(?:[ \t]*\d+\t|[^\s:]+:\d+:|\d+[:-])?"  # read_file numbers, grep/search "file:12:" or "12:"
_YAML_BLOCK = re.compile(r"""(?im)^(?P<head>""" + _LINE_PREFIX + r"""(?P<ind>[ \t]*)""" + _SECRET_NAME
                         + r""":[ \t]*[|>][-+0-9]*[ \t]*\n)(?P<body>(?:""" + _LINE_PREFIX
                         + r"""(?P=ind)[ \t]+\S[^\n]*(?:\n|$))+)""")

# Well-known token formats even when no key name precedes them (JWT, GitHub, OpenAI/Anthropic,
# Stripe/ElevenLabs style, AWS, Slack, Telegram bots, OpsGate license keys).
_TOKENS = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}"
    r"|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}"
    r"|\b(?:sk|rk|whsec)_(?:live_|test_)?[A-Za-z0-9]{24,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[abprs]-[A-Za-z0-9-]{10,}"
    r"|\b\d{8,10}:[A-Za-z0-9_-]{35}\b"
    r"|\bog_[A-Za-z0-9_-]{30,}"
    r"|\bAIza[0-9A-Za-z_-]{35}")

MARKER = "***"
PEM_MARKER = "[PRIVATE KEY HIDDEN]"
TOKEN_MARKER = "[TOKEN HIDDEN]"
_MARKER_RX = re.compile(
    r"\[PRIVATE KEY HIDDEN\]|\[TOKEN HIDDEN\]|(?:bearer|basic) \*\*\*|:\*\*\*@"
    r"|" + _SECRET_NAME + r"[\"']?\s*(?:=>|[=:,]|[ \t])\s*[\"']?\*\*\*", re.I)


def redact(text: str) -> str:
    text = _PEM.sub(PEM_MARKER, text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} ***", text)
    text = _URLCRED.sub(r"\1:***@", text)
    text = _YAML_BLOCK.sub(lambda m: m.group("head") + "  " + MARKER + "\n", text)
    text = _PGPASS.sub(lambda m: m.group(1) + MARKER, text)
    text = _KV.sub(lambda m: m.group(1) + MARKER, text)
    text = _KV_CALL.sub(lambda m: m.group(1) + MARKER, text)
    text = _KV_LINE.sub(lambda m: m.group(1) + MARKER, text)
    for rx in (_NETRC, _XML, _KEY_VALUE_ATTR, _MYSQL_P, _AUTHZ, _CURL_U, _CLI_LONG, _CLI_SHORT):
        text = rx.sub(lambda m: m.group(1) + MARKER, text)
    text = _TOKENS.sub(TOKEN_MARKER, text)
    return text


_PROBE = "OgZ9pr0beZ9Xq7"  # looks like a secret value to every rule above


def has_redaction_marker(text: str) -> bool:
    """True if the text carries redaction markers (it came from a read with hidden secrets).
    A *** counts when redact() would hide something at that very place: each *** is replaced by a
    probe value and redacted again, so detection follows every redaction rule automatically."""
    if PEM_MARKER in text or TOKEN_MARKER in text or _MARKER_RX.search(text):
        return True
    if MARKER not in text:
        return False
    for wrapped in (_PROBE, f'"{_PROBE}"', f"'{_PROBE}'"):  # rules that hide a quoted value whole
        probe = text.replace(MARKER, wrapped)
        if redact(probe).count(_PROBE) < probe.count(_PROBE):
            return True
    return False


def truncate(text: str, limit: int | None = None) -> str:
    limit = limit or cfg.max_output_chars
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated: {len(text) - limit} more characters]"


# ---------------------------------------------------------------- paths
def _within(p: Path, roots: list[Path]) -> bool:
    return any(p == r or r in p.parents for r in roots)


def is_denied_name(p: Path) -> bool:
    return any(fnmatch.fnmatch(p.name, pat) for pat in cfg.deny_names)


# With write_roots defaulting to "/", these system directories can never be the DIRECT target of
# a modifying operation (mv/chmod/ln on the directory itself). Their CONTENTS stay reachable
# (e.g. /etc/nginx/nginx.conf); only the system directory node itself is protected.
SYSTEM_ROOTS = frozenset(Path(p) for p in (
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/media", "/mnt",
    "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var"))
ALLOWED_NAME_RE = re.compile(r"^[A-Za-z0-9_.@:-]+$")  # valid service/unit name


def resolve_inside(path: str, roots: list[Path], *, allow_denied: bool = False) -> Path:
    """Resolve (following symlinks) and require the result to be inside roots."""
    if not path or "\x00" in path:
        raise ValueError("Invalid path")
    raw = Path(path)
    if not raw.is_absolute():
        raise ValueError("Use an absolute path")
    p = raw.resolve()
    if not _within(p, roots):
        raise ValueError(f"Path outside the allowed folders: {p}")
    if not allow_denied and is_denied_name(p):
        raise ValueError(f"Protected file (secrets/keys): {p.name}")
    check_readable(p)
    return p


def agent_protected() -> list[Path]:
    """The agent's own state, audit log, backups, code and configuration: never writable through
    the tools (a misled assistant must not reset its usage counter or edit its own audit trail)."""
    out = []
    for p in (cfg.state_dir, cfg.audit_file.parent, cfg.backup_dir, Path("/etc/opsgate"), Path("/opt/opsgate")):
        try:
            out.append(Path(p).resolve())
        except OSError:
            pass
    return out


def agent_private() -> list[Path]:
    """The agent's configuration and state: not even readable through the tools."""
    out = []
    for q in (cfg.state_dir, Path("/etc/opsgate")):
        try:
            out.append(Path(q).resolve())
        except OSError:
            pass
    return out


def check_readable(p: Path) -> None:
    if _within(p, agent_private()):
        raise ValueError(f"OpsGate's own configuration is not readable through the tools: {p}")


def check_writable(p: Path) -> None:
    if _within(p, agent_protected()):
        raise ValueError(f"OpsGate's own files cannot be modified through the tools: {p}")


# ---------------------------------------------------------------- rate limit
_calls: collections.deque[float] = collections.deque()
_lock = threading.Lock()


_per_client: dict[str, collections.deque[float]] = {}


def _client_key() -> str:
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
        tok = get_access_token()
        return tok.client_id if tok else "anonymous"
    except Exception:  # noqa: BLE001
        return "anonymous"


def rate_limit(client: str | None = None) -> None:
    """MCP_RATE_PER_MIN per connected app (OAuth client or static tokens), 3x that for the server."""
    now = time.monotonic()
    key = client or _client_key()
    with _lock:
        dq = _per_client.setdefault(key, collections.deque())
        for q in (_calls, dq):
            while q and now - q[0] > 60:
                q.popleft()
        if len(dq) >= cfg.rate_per_minute or len(_calls) >= 3 * cfg.rate_per_minute:
            raise ValueError("Too many requests per minute; wait a moment")
        dq.append(now)
        _calls.append(now)
        if len(_per_client) > 1000:
            for k in [k for k, q in _per_client.items() if not q][:500]:
                _per_client.pop(k, None)


def reset_rate_limit() -> None:
    with _lock:
        _calls.clear()
        _per_client.clear()


# ---------------------------------------------------------------- decorator
def guard(name: str, metered: bool = True) -> Callable:
    """Usage metering + audit + rate limit + redaction + truncation, running in a worker thread.
    metered=False only for account_status, so users can always see their usage."""

    def deco(fn: Callable) -> Callable:
        sig = inspect.signature(fn)

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            import meter  # late import: meter imports config only, keeps tests able to swap it

            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)
            t0 = time.monotonic()
            try:
                if metered:
                    await anyio.to_thread.run_sync(meter.METER.before_call)  # may raise QuotaError
                rate_limit()
                if metered:
                    meter.METER.count()
                result = await anyio.to_thread.run_sync(lambda: fn(*args, **kwargs))
                out = truncate(redact(str(result)))
                audit.log(name, params, True, int((time.monotonic() - t0) * 1000))
                return out
            except Exception as e:  # the message is redacted before it is returned
                audit.log(name, params, False, int((time.monotonic() - t0) * 1000), note=str(e))
                raise ValueError(truncate(redact(str(e)), 2000)) from None

        return wrapper

    return deco
