"""Two-step verification on the agent's own login page."""
import hashlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from test_oauth import CB, PASSWORD, _free_port, pkce, register, start_auth
import totp
from oauth import hash_password

ROOT = Path(__file__).resolve().parent.parent
SECRET = totp.new_secret()


@pytest.fixture(scope="module")
def srv2(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("totp")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {"PATH": os.environ["PATH"], "OPSGATE_METERING": "off", "MCP_ADMIN_PASSWORD_HASH": hash_password(PASSWORD, n=2**14),
           "MCP_TOTP_SECRET": SECRET, "MCP_STATE_DIR": str(tmp / "state"), "MCP_READ_ROOTS": str(tmp),
           "MCP_WRITE_ROOTS": str(tmp), "MCP_LOG_ROOTS": str(tmp), "MCP_BACKUP_DIR": str(tmp / "bk"),
           "MCP_AUDIT_FILE": str(tmp / "a" / "audit.jsonl"), "MCP_PORT": str(port), "MCP_PUBLIC_URL": base}
    p = subprocess.Popen([sys.executable, "server.py"], cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        p.kill()
        pytest.fail(p.stdout.read().decode())
    yield base
    p.terminate()
    p.wait(timeout=10)


def begin(base):
    cid = register(base).json()["client_id"]
    _, c = pkce()
    return start_auth(base, cid, c).headers["location"]


def post(base, loc, password, code=None):
    req = parse_qs(urlparse(loc).query)["req"][0]
    data = {"req": req, "password": password, "action": "allow"}
    if code is not None:
        data["code"] = code
    return httpx.post(f"{base}/oauth/login", data=data)


def test_login_page_asks_for_the_code(srv2):
    page = httpx.get(begin(srv2))
    assert 'name="code"' in page.text and "authenticator" in page.text


def test_password_alone_is_not_enough(srv2):
    for code in (None, "", "000000"):
        r = post(srv2, begin(srv2), PASSWORD, code)
        assert r.status_code == 200 and "Wrong password or code" in r.text   # never a redirect with a code


def test_right_password_and_code_pass_once_only(srv2):
    code = totp._code(SECRET, int(time.time() // 30) + 1)
    r = post(srv2, begin(srv2), PASSWORD, code)
    assert r.status_code == 302 and r.headers["location"].startswith(CB)
    r = post(srv2, begin(srv2), PASSWORD, code)       # same code again: replay
    assert r.status_code == 200 and "Wrong password or code" in r.text


def test_code_without_password_fails(srv2):
    r = post(srv2, begin(srv2), "wrong-password", totp._code(SECRET, int(time.time() // 30)))
    assert r.status_code == 200 and "Wrong password or code" in r.text
