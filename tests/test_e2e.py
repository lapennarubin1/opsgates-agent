"""Arranca el servidor real (HTTP + Bearer) y lo usa con el cliente MCP oficial."""
import asyncio
import hashlib
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "tok-de-prueba-" + "a" * 40


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("e2e")
    staging = tmp / "staging"
    staging.mkdir()
    (staging / "hola.txt").write_text("linea1\npassword=NoDebeVerse\nlinea3\n")
    (staging / ".env").write_text("TOKEN=zzz")
    port = _free_port()
    env = {
        "PATH": os.environ["PATH"], "OPSGATE_METERING": "off",
        "MCP_TOKEN_SHA256": hashlib.sha256(TOKEN.encode()).hexdigest(),
        "MCP_READ_ROOTS": str(staging), "MCP_WRITE_ROOTS": str(staging),
        "MCP_LOG_ROOTS": str(tmp), "MCP_BACKUP_DIR": str(tmp / "bk"),
        "MCP_AUDIT_FILE": str(tmp / "audit" / "audit.jsonl"),
        "MCP_PORT": str(port), "MCP_PUBLIC_URL": f"http://127.0.0.1:{port}",
    }
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
        pytest.fail("El servidor no arrancó: " + p.stdout.read().decode())
    yield {"url": f"http://127.0.0.1:{port}/mcp", "staging": staging, "tmp": tmp}
    p.terminate()
    p.wait(timeout=10)


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
HDR = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def test_sin_token_rechazado(server):
    r = httpx.post(server["url"], json=INIT, headers=HDR)
    assert r.status_code == 401


def test_token_incorrecto_rechazado(server):
    r = httpx.post(server["url"], json=INIT, headers={**HDR, "Authorization": "Bearer incorrecto"})
    assert r.status_code == 401


def test_host_raro_rechazado(server):
    r = httpx.post(server["url"], json=INIT,
                   headers={**HDR, "Authorization": f"Bearer {TOKEN}", "Host": "evil.example.com"})
    assert r.status_code in (400, 421)


def test_token_correcto_y_herramientas(server):
    async def go():
        async with streamablehttp_client(server["url"], headers={"Authorization": f"Bearer {TOKEN}"}) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                tools = {t.name: t for t in (await s.list_tools()).tools}
                assert len(tools) == 18
                assert tools["read_file"].annotations.readOnlyHint is True
                assert tools["write_file"].annotations.destructiveHint is True

                f = str(server["staging"] / "hola.txt")
                res = await s.call_tool("read_file", {"path": f})
                text = res.content[0].text
                assert "linea1" in text and "NoDebeVerse" not in text  # redactado

                res = await s.call_tool("read_file", {"path": str(server["staging"] / ".env")})
                assert res.isError

                res = await s.call_tool("read_file", {"path": "/etc/passwd"})
                assert res.isError

                res = await s.call_tool("write_file", {"path": f, "content": "nuevo\n"})
                assert "NOT written" in res.content[0].text
                assert "linea1" in (server["staging"] / "hola.txt").read_text()

                res = await s.call_tool("write_file", {"path": f, "content": "nuevo\n", "confirm": True})
                assert (server["staging"] / "hola.txt").read_text() == "nuevo\n"
                assert len(list((server["tmp"] / "bk").iterdir())) == 1

                res = await s.call_tool("run_command", {"command": "ls", "cwd": str(server["staging"])})
                assert "hola.txt" in res.content[0].text

                res = await s.call_tool("run_command", {"command": "rm hola.txt", "cwd": str(server["staging"])})
                assert res.isError

                # Reescribir con el contenido redactado está prohibido (borraría secretos)
                (server["staging"] / "cfg.conf").write_text("password=Real1\nhost=a\n")
                res = await s.call_tool("read_file", {"path": str(server["staging"] / "cfg.conf")})
                assert "Real1" not in res.content[0].text
                res = await s.call_tool("write_file", {"path": str(server["staging"] / "cfg.conf"),
                                                       "content": "password=***\nhost=b\n", "confirm": True})
                assert res.isError and "Real1" in (server["staging"] / "cfg.conf").read_text()

                # Los errores también salen redactados
                res = await s.call_tool("read_file", {"path": "/no/existe/password=filtrada"})
                assert res.isError and "filtrada" not in res.content[0].text

    asyncio.run(go())
    audit = (server["tmp"] / "audit" / "audit.jsonl").read_text()
    assert '"tool": "write_file"' in audit and "NoDebeVerse" not in audit
