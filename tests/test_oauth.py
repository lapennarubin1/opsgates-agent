"""Flujo OAuth completo contra el servidor real (como lo haría claude.ai): registro, login, PKCE,
tokens, refresh con rotación, revocación, y los ataques típicos (redirect ajeno, código reusado...)."""
import base64
import hashlib
import os
import re
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from oauth import hash_password, redirect_allowed, verify_password  # noqa: E402

PASSWORD = "contraseña-de-prueba-larga"
STATIC = "tok-estatico-" + "b" * 40
CB = "https://claude.ai/api/mcp/auth_callback"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
HDR = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def srv(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("oauth")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {"PATH": os.environ["PATH"], "OPSGATE_METERING": "off", "MCP_TOKEN_SHA256": hashlib.sha256(STATIC.encode()).hexdigest(),
           "MCP_ADMIN_PASSWORD_HASH": hash_password(PASSWORD, n=2**14), "MCP_STATE_DIR": str(tmp / "state"),
           "MCP_READ_ROOTS": str(tmp), "MCP_WRITE_ROOTS": str(tmp), "MCP_LOG_ROOTS": str(tmp),
           "MCP_BACKUP_DIR": str(tmp / "bk"), "MCP_AUDIT_FILE": str(tmp / "a" / "audit.jsonl"),
           "MCP_PORT": str(port), "MCP_PUBLIC_URL": base}
    p = subprocess.Popen([sys.executable, "server.py"], cwd=ROOT, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        p.kill()
        pytest.fail(p.stdout.read().decode())
    yield {"base": base, "tmp": tmp}
    p.terminate()
    p.wait(timeout=10)


def pkce():
    v = secrets.token_urlsafe(48)
    c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
    return v, c


def register(base, uris=(CB,)):
    return httpx.post(f"{base}/register", json={"redirect_uris": list(uris), "client_name": "Claude",
                                                "token_endpoint_auth_method": "none",
                                                "grant_types": ["authorization_code", "refresh_token"]})


def start_auth(base, cid, challenge, resource=None):
    r = httpx.get(f"{base}/authorize", params={
        "response_type": "code", "client_id": cid, "redirect_uri": CB, "code_challenge": challenge,
        "code_challenge_method": "S256", "state": "st123", "resource": resource or f"{base}/mcp"})
    return r


def login(base, login_url, password):
    req = parse_qs(urlparse(login_url).query)["req"][0]
    return httpx.post(f"{base}/oauth/login", data={"req": req, "password": password, "action": "allow"}), req


def full_flow(base):
    cid = register(base).json()["client_id"]
    v, c = pkce()
    r = start_auth(base, cid, c)
    assert r.status_code == 302 and "/oauth/login?req=" in r.headers["location"]
    r2, _ = login(base, r.headers["location"], PASSWORD)
    assert r2.status_code == 302 and r2.headers["location"].startswith(CB)
    q = parse_qs(urlparse(r2.headers["location"]).query)
    assert q["state"] == ["st123"]
    tok = httpx.post(f"{base}/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                            "redirect_uri": CB, "client_id": cid, "code_verifier": v,
                                            "resource": f"{base}/mcp"})
    assert tok.status_code == 200, tok.text
    return cid, v, q["code"][0], tok.json()


def mcp_ok(base, token):
    return httpx.post(f"{base}/mcp", json=INIT, headers={**HDR, "Authorization": f"Bearer {token}"}).status_code


# ------------------------------------------------------------------ unidades
def test_password_hash():
    h = hash_password("abc-123-xyz-long", n=2**14)
    assert verify_password("abc-123-xyz-long", h) and not verify_password("otra", h)
    assert "abc-123" not in h and not verify_password("x", "basura")


@pytest.mark.parametrize("uri,ok", [
    (CB, True), ("https://chatgpt.com/connector_platform_oauth_redirect", True), ("http://localhost:33418/cb", True),
    ("http://claude.ai/x", False), ("https://claude.ai.evil.com/cb", False), ("https://evil.com/cb", False),
    ("https://evilclaude.ai/cb", False), ("javascript:alert(1)", False),
    ("cursor://anysphere.cursor-mcp/oauth/callback", True), ("vscode://vscode.github-authentication/cb", True),
    ("data:text/html,x", False), ("file:///etc/passwd", False), ("cursor://evil.example/cb", False),
    ("vscode://evil/cb", False), ("windsurf://anything/cb", False)])
def test_redirects(uri, ok):
    assert redirect_allowed(uri, ["claude.ai", "chatgpt.com", "localhost"]) is ok


def test_native_schemes_need_desktop_clients():
    assert redirect_allowed("cursor://anysphere.cursor-mcp/oauth/callback", ["claude.ai"]) is False


# ------------------------------------------------------------------ servidor real
def test_metadata_y_401(srv):
    b = srv["base"]
    m = httpx.get(f"{b}/.well-known/oauth-authorization-server").json()
    assert m["registration_endpoint"].endswith("/register") and "S256" in m["code_challenge_methods_supported"]
    r = httpx.post(f"{b}/mcp", json=INIT, headers=HDR)
    assert r.status_code == 401 and "resource_metadata" in r.headers.get("www-authenticate", "")
    pr = httpx.get(f"{b}/.well-known/oauth-protected-resource/mcp")
    assert pr.status_code == 200 and pr.json()["resource"].rstrip("/") == f"{b}/mcp"


def test_flujo_completo_refresh_y_revocacion(srv):
    b = srv["base"]
    cid, v, code, t = full_flow(b)
    assert mcp_ok(b, t["access_token"]) == 200
    # el código es de un solo uso
    again = httpx.post(f"{b}/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                           "client_id": cid, "code_verifier": v})
    assert again.status_code == 400
    # refresh con rotación
    r = httpx.post(f"{b}/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                       "client_id": cid})
    assert r.status_code == 200, r.text
    t2 = r.json()
    assert mcp_ok(b, t2["access_token"]) == 200
    old = httpx.post(f"{b}/token", data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"],
                                         "client_id": cid})
    assert old.status_code == 400
    # revocación
    # (el SDK exige el campo client_secret en /revoke aunque el cliente sea público: va vacío)
    rv = httpx.post(f"{b}/revoke", data={"token": t2["access_token"], "client_id": cid, "client_secret": ""})
    assert rv.status_code == 200
    assert mcp_ok(b, t2["access_token"]) == 401


def test_tokens_solo_como_hash_en_disco(srv):
    _, _, _, t = full_flow(srv["base"])
    raw = (srv["tmp"] / "state" / "oauth.db").read_bytes()
    for f in ("access_token", "refresh_token"):
        assert t[f].encode() not in raw
    assert PASSWORD.encode() not in raw
    assert oct((srv["tmp"] / "state" / "oauth.db").stat().st_mode)[-3:] == "600"


def test_password_incorrecta_y_bloqueo_por_solicitud(srv):
    b = srv["base"]
    cid = register(b).json()["client_id"]
    _, c = pkce()
    loc = start_auth(b, cid, c).headers["location"]
    for _ in range(4):
        r, _ = login(b, loc, "mala")
        assert r.status_code == 200 and "Wrong password" in r.text
    r, _ = login(b, loc, "mala")
    assert r.status_code == 403
    r, _ = login(b, loc, PASSWORD)  # la solicitud ya no vale aunque ahora acierte
    assert r.status_code == 400


def test_rechazar(srv):
    b = srv["base"]
    cid = register(b).json()["client_id"]
    _, c = pkce()
    loc = start_auth(b, cid, c).headers["location"]
    req = parse_qs(urlparse(loc).query)["req"][0]
    r = httpx.post(f"{b}/oauth/login", data={"req": req, "action": "deny"})
    assert r.status_code == 302 and "error=access_denied" in r.headers["location"]


def test_registro_con_redirect_ajeno_rechazado(srv):
    r = register(srv["base"], uris=("https://evil.com/cb",))
    assert r.status_code == 400 and "invalid_redirect_uri" in r.text


def test_resource_de_otro_servidor_rechazado(srv):
    b = srv["base"]
    cid = register(b).json()["client_id"]
    _, c = pkce()
    r = start_auth(b, cid, c, resource="https://otro-servidor.com/mcp")
    assert r.status_code in (302, 400) and "/oauth/login" not in r.headers.get("location", "")


def test_pkce_incorrecto(srv):
    b = srv["base"]
    cid = register(b).json()["client_id"]
    _, c = pkce()
    loc = start_auth(b, cid, c).headers["location"]
    r, _ = login(b, loc, PASSWORD)
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    t = httpx.post(f"{b}/token", data={"grant_type": "authorization_code", "code": code, "redirect_uri": CB,
                                       "client_id": cid, "code_verifier": "x" * 50})
    assert t.status_code == 400


def test_token_estatico_sigue_valiendo(srv):
    assert mcp_ok(srv["base"], STATIC) == 200
    assert mcp_ok(srv["base"], "inventado-" + "c" * 40) == 401


def test_login_sin_req_y_cabeceras(srv):
    r = httpx.get(f"{srv['base']}/oauth/login?req=noexiste")
    assert r.status_code == 400 and r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_xss_en_nombre_de_cliente(srv):
    b = srv["base"]
    r = httpx.post(f"{b}/register", json={"redirect_uris": [CB], "client_name": "<script>alert(1)</script>",
                                          "token_endpoint_auth_method": "none"})
    cid = r.json()["client_id"]
    _, c = pkce()
    loc = start_auth(b, cid, c).headers["location"]
    page = httpx.get(loc)
    assert "<script>" not in page.text and "&lt;script&gt;" in page.text
    assert re.search(r"sent back to: <b>claude\.ai</b>", page.text)
