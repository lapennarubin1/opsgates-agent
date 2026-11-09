"""Built-in OAuth 2.1 server: OpsGate's own login for claude.ai, ChatGPT and any MCP client.

Everything lives on the machine where the agent is installed: no third party is involved.
- The owner's password is stored only as a scrypt hash (MCP_ADMIN_PASSWORD_HASH).
- Codes, access and refresh tokens are stored only as SHA-256 in SQLite (MCP_STATE_DIR/oauth.db).
- PKCE required (enforced by the SDK), single-use 5-minute codes, rotating refresh tokens.
- Dynamic client registration (RFC 7591) only with redirect URIs on allowed hosts.
- Static tokens (MCP_TOKEN_SHA256) keep working for Claude Code / Codex / scripts.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import totp
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError, RefreshToken,
    RegistrationError, TokenError, construct_redirect_uri)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

SCOPE = "ops"
CODE_TTL = 300
PENDING_TTL = 600
ACCESS_TTL = 3600
REFRESH_TTL = 30 * 86400
MAX_CLIENTS = 500
MAX_TRIES_PER_REQUEST = 5
LOCKOUT_FAILS, LOCKOUT_WINDOW = 10, 900  # 10 failures in 15 min lock the login for 15 min

DEFAULT_REDIRECT_HOSTS = ["claude.ai", "claude.com", "chatgpt.com", "chat.openai.com", "vscode.dev",
                          "insiders.vscode.dev", "localhost", "127.0.0.1"]
# Private-use URI schemes of desktop editors (RFC 8252 native apps), each limited to the editor's
# own callback authority. Allowed whenever local desktop clients are (localhost in the redirect
# hosts). PKCE still applies.
NATIVE_REDIRECTS = {"cursor": ("anysphere.cursor-mcp",), "vscode": ("vscode.",), "vscode-insiders": ("vscode.",)}
NATIVE_SCHEMES = tuple(NATIVE_REDIRECTS)


def _h(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------- password (scrypt, stdlib only)
def hash_password(password: str, n: int = 2**15, r: int = 8, p: int = 1) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=64 * 1024 * 1024, dklen=32)
    return f"scrypt:{n}:{r}:{p}:{salt.hex()}:{dk.hex()}"  # no "$": safe in EnvironmentFile and shells


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, dk = stored.strip().split(":")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              maxmem=64 * 1024 * 1024, dklen=len(bytes.fromhex(dk)))
        return hmac.compare_digest(calc, bytes.fromhex(dk))
    except (ValueError, TypeError):
        return False


def redirect_allowed(uri: str, hosts: list[str]) -> bool:
    try:
        u = urlparse(uri)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    scheme = (u.scheme or "").lower()
    if scheme in NATIVE_REDIRECTS:
        ok_host = any(host == a or (a.endswith(".") and host.startswith(a)) for a in NATIVE_REDIRECTS[scheme])
        return ok_host and "localhost" in hosts
    if host in ("localhost", "127.0.0.1"):
        return host in hosts and scheme in ("http", "https")  # desktop/CLI clients
    return scheme == "https" and any(host == h or host.endswith("." + h) for h in hosts)


class LocalOAuthProvider:
    def __init__(self, db_path: Path, public_url: str, resource_url: str, password_hash: str,
                 static_hashes: list[str], redirect_hosts: list[str] | None = None, totp_secret: str = ""):
        self.public_url = public_url.rstrip("/")
        self.resource_url = resource_url.rstrip("/")
        self.password_hash = password_hash
        self.totp_secret = totp_secret.strip().replace(" ", "")
        self._totp_last = 0  # newest accepted time step: a code works once
        self.static_hashes = [h.lower() for h in static_hashes]
        self.redirect_hosts = [h.lower() for h in (redirect_hosts or DEFAULT_REDIRECT_HOSTS)]
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}  # per source address: one party cannot lock out the owner
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(db_path), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        for t in ("clients", "pending", "codes", "access", "refresh"):
            self.db.execute(f"CREATE TABLE IF NOT EXISTS {t} (k TEXT PRIMARY KEY, v TEXT NOT NULL, exp REAL)")
        try:
            db_path.chmod(0o600)
        except OSError:
            pass

    # ------------------------------------------------------------ storage
    def _put(self, table: str, key: str, value: dict, exp: float | None) -> None:
        with self._lock:
            self.db.execute(f"INSERT OR REPLACE INTO {table} VALUES (?,?,?)", (key, json.dumps(value), exp))

    def _get(self, table: str, key: str) -> dict | None:
        with self._lock:
            row = self.db.execute(f"SELECT v, exp FROM {table} WHERE k=?", (key,)).fetchone()
        if not row:
            return None
        if row[1] is not None and row[1] < time.time():
            self._del(table, key)
            return None
        return json.loads(row[0])

    def _del(self, table: str, key: str) -> None:
        with self._lock:
            self.db.execute(f"DELETE FROM {table} WHERE k=?", (key,))

    def _purge(self) -> None:
        with self._lock:
            for t in ("pending", "codes", "access", "refresh"):
                self.db.execute(f"DELETE FROM {t} WHERE exp IS NOT NULL AND exp < ?", (time.time(),))

    # ------------------------------------------------------------ clients (dynamic registration)
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        d = self._get("clients", client_id)
        return OAuthClientInformationFull.model_validate(d) if d else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not redirect_allowed(str(uri), self.redirect_hosts):
                raise RegistrationError("invalid_redirect_uri",
                                        f"Redirect URI not allowed: {uri}. See MCP_OAUTH_REDIRECT_HOSTS")
        with self._lock:
            n = self.db.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        if n >= MAX_CLIENTS:
            raise RegistrationError("invalid_client_metadata", "Too many registered clients")
        self._put("clients", client_info.client_id, client_info.model_dump(mode="json"), None)

    # ------------------------------------------------------------ authorization (goes through the login page)
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") != self.resource_url:
            raise AuthorizeError("invalid_request", "resource does not match this server")
        if not redirect_allowed(str(params.redirect_uri), self.redirect_hosts):
            raise AuthorizeError("invalid_request", "redirect_uri not allowed")
        self._purge()
        req = secrets.token_urlsafe(32)
        self._put("pending", req, {"client_id": client.client_id, "params": params.model_dump(mode="json"),
                                   "tries": 0}, time.time() + PENDING_TTL)
        return f"{self.public_url}/oauth/login?req={req}"

    GLOBAL_FAILS = 100  # ceiling across all addresses (distributed guessing)

    @staticmethod
    def _ip(request: Request) -> str:
        import ipaddress
        peer = request.client.host if request.client else ""
        try:
            local = ipaddress.ip_address(peer).is_private
        except ValueError:
            return peer
        if local:  # behind our own reverse proxy: the right-most address that is not private
            for part in reversed([p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]):
                try:
                    if not ipaddress.ip_address(part).is_private:
                        return part
                except ValueError:
                    break
        return peer

    def _fail_count(self, ip: str) -> tuple[int, int]:
        now = time.time()
        total = 0
        for k in list(self._fails):
            self._fails[k] = [t for t in self._fails[k] if now - t < LOCKOUT_WINDOW]
            if not self._fails[k]:
                del self._fails[k]
            else:
                total += len(self._fails[k])
        return len(self._fails.get(ip, [])), total

    def _locked(self, ip: str) -> bool:
        mine, total = self._fail_count(ip)
        return mine >= LOCKOUT_FAILS or total >= self.GLOBAL_FAILS

    def _credentials_ok(self, password: str, code: str) -> bool:
        """Password, plus the current authenticator code when two-step verification is on (both are always
        checked, so the answer does not reveal which one was wrong)."""
        ok = verify_password(password, self.password_hash)
        if not self.totp_secret:
            return ok
        with self._lock:
            step = totp.verify(self.totp_secret, code, self._totp_last)
            if step is not None and ok:
                self._totp_last = step
                return True
        return False

    async def login_page(self, request: Request) -> Response:
        req = request.query_params.get("req", "") if request.method == "GET" else ""
        form = {}
        if request.method == "POST":
            form = await request.form()
            req = str(form.get("req", ""))
        pending = self._get("pending", req) if req else None
        if not pending:
            return _page("Request expired or invalid", "<p>Reconnect the connector from your app.</p>",
                         400)
        client = await self.get_client(pending["client_id"])
        params = AuthorizationParams.model_validate(pending["params"])
        who = html.escape(client.client_name or client.client_id if client else "?")
        dest = html.escape(urlparse(str(params.redirect_uri)).hostname or "")
        error = ""
        ip = self._ip(request)
        if request.method == "POST":
            if self._locked(ip):
                error = "Too many failed attempts. Wait 15 minutes."
            elif str(form.get("action", "")) == "deny":
                self._del("pending", req)
                return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), error="access_denied",
                                                               state=params.state), status_code=302)
            elif self._credentials_ok(str(form.get("password", "")), str(form.get("code", ""))):
                self._del("pending", req)
                code = secrets.token_urlsafe(32)
                ac = AuthorizationCode(code="", scopes=params.scopes or [SCOPE], expires_at=time.time() + CODE_TTL,
                                       client_id=pending["client_id"], code_challenge=params.code_challenge,
                                       redirect_uri=params.redirect_uri,
                                       redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                                       resource=self.resource_url, subject="owner")
                self._put("codes", _h(code), ac.model_dump(mode="json"), ac.expires_at)
                return RedirectResponse(construct_redirect_uri(str(params.redirect_uri), code=code,
                                                               state=params.state), status_code=302)
            else:
                self._fails.setdefault(ip, []).append(time.time())
                pending["tries"] += 1
                if pending["tries"] >= MAX_TRIES_PER_REQUEST:
                    self._del("pending", req)
                    return _page("Access blocked", "<p>Too many attempts. Reconnect from your app.</p>",
                                 403)
                self._put("pending", req, pending, time.time() + PENDING_TTL)
                error = "Wrong password or code." if self.totp_secret else "Wrong password."
        code_field = ('<label>Code from your authenticator app<input type="text" name="code" inputmode="numeric" '
                      'autocomplete="one-time-code" maxlength="8" required></label>') if self.totp_secret else ""
        body = f"""
<p><b>{who}</b> is requesting access to this OpsGate server.</p>
<p class="muted">You will be sent back to: <b>{dest}</b>. If you did not start this connection, click Deny.</p>
{f'<p class="err">{html.escape(error)}</p>' if error else ''}
<form method="post" autocomplete="off">
  <input type="hidden" name="req" value="{html.escape(req)}">
  <label>Password<input type="password" name="password" autofocus required></label>{code_field}
  <div class="row"><button name="action" value="allow">Allow</button>
  <button name="action" value="deny" class="sec" formnovalidate>Deny</button></div>
</form>"""
        return _page("Authorize access", body, 200)

    # ------------------------------------------------------------ codes and tokens
    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str):
        d = self._get("codes", _h(authorization_code))
        if not d or d["client_id"] != client.client_id:
            return None
        d["code"] = authorization_code
        return AuthorizationCode.model_validate(d)

    def _issue(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        now = time.time()
        meta = {"client_id": client_id, "scopes": scopes, "resource": self.resource_url, "subject": "owner"}
        self._put("access", _h(access), {**meta, "expires_at": int(now + ACCESS_TTL)}, now + ACCESS_TTL)
        self._put("refresh", _h(refresh), {**meta, "expires_at": int(now + REFRESH_TTL)}, now + REFRESH_TTL)
        return OAuthToken(access_token=access, token_type="Bearer", expires_in=ACCESS_TTL,
                          refresh_token=refresh, scope=" ".join(scopes))

    async def exchange_authorization_code(self, client, authorization_code: AuthorizationCode) -> OAuthToken:
        key = _h(authorization_code.code)
        if not self._get("codes", key):  # single use
            raise TokenError("invalid_grant", "code already used or expired")
        self._del("codes", key)
        return self._issue(client.client_id, authorization_code.scopes)

    async def load_refresh_token(self, client, refresh_token: str):
        d = self._get("refresh", _h(refresh_token))
        if not d or d["client_id"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, **d)

    async def exchange_refresh_token(self, client, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        self._del("refresh", _h(refresh_token.token))  # rotation: the old refresh token stops working
        return self._issue(client.client_id, scopes or refresh_token.scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        digest = _h(token)
        ok = False
        for good in self.static_hashes:  # static token (Claude Code, Codex, scripts)
            ok |= hmac.compare_digest(digest, good)
        if ok:
            return AccessToken(token="***", client_id="static", scopes=[SCOPE], expires_at=None,
                               resource=self.resource_url, subject="owner")
        d = self._get("access", digest)
        return AccessToken(token=token, **d) if d else None  # real token: revoke_token needs it

    async def revoke_token(self, token) -> None:
        raw = getattr(token, "token", None)
        if raw and raw != "***":
            self._del("access", _h(raw))
            self._del("refresh", _h(raw))

    def revoke_all(self) -> int:
        with self._lock:
            n = sum(self.db.execute(f"DELETE FROM {t}").rowcount for t in ("access", "refresh", "codes", "pending"))
        return n


LOGO_SVG = ('<svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><rect x="2" y="2" width="20" height="20" rx="6" '
            'fill="currentColor" opacity=".12"/><path d="M7 18V9a5 5 0 0 1 10 0v9" stroke="currentColor" '
            'stroke-width="2" stroke-linecap="round"/><path d="M12 13v5" stroke="currentColor" stroke-width="2" '
            'stroke-linecap="round"/></svg>')


def _page(title: str, body: str, status: int) -> HTMLResponse:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>
<style>
:root{{--bg:#f6f6f4;--card:#fff;--fg:#1d1d1b;--mut:#6b6b66;--acc:#1f5eff;--err:#b42318;--bd:#e3e3df}}
@media (prefers-color-scheme:dark){{:root{{--bg:#141413;--card:#1e1e1c;--fg:#ededea;--mut:#a3a39d;--acc:#6f95ff;--err:#ff8a7a;--bd:#33332f}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px;box-sizing:border-box}}
main{{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:28px;max-width:420px;width:100%}}
h1{{font-size:20px;margin:0 0 12px}}.muted{{color:var(--mut);font-size:14px}}.err{{color:var(--err)}}
label{{display:block;margin:16px 0}}input{{display:block;width:100%;box-sizing:border-box;margin-top:6px;padding:10px;border:1px solid var(--bd);border-radius:8px;background:transparent;color:inherit;font:inherit}}
.row{{display:flex;gap:8px}}button{{flex:1;padding:10px;border-radius:8px;border:0;background:var(--acc);color:#fff;font:inherit;cursor:pointer}}
button.sec{{background:transparent;color:var(--fg);border:1px solid var(--bd)}}
.brand{{display:flex;align-items:center;gap:8px;font-weight:600;margin-bottom:18px;color:var(--fg)}}
.brand svg{{width:22px;height:22px}}.foot{{margin-top:20px;font-size:12px;color:var(--mut)}}
</style></head><body><main><div class="brand">{LOGO_SVG}<span>OpsGate</span></div>
<h1>{html.escape(title)}</h1>{body}
<p class="foot">This login runs on your own server. Your password never leaves it.</p></main></body></html>"""
    return HTMLResponse(doc, status_code=status, headers={
        "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"})
