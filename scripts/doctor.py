#!/usr/bin/env python3
"""End-to-end check of an installed agent.   sudo opsgate doctor [--token TOKEN]

Without a token it checks the service from the outside (authentication required, OAuth discovery,
sign-in page, public HTTPS address, link with OpsGate Cloud). With a static token
(`sudo opsgate token create doctor`) it also calls the tools and checks the guard rails."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
import warnings

import httpx

warnings.filterwarnings("ignore", category=DeprecationWarning)
results: list[tuple[bool, str, str]] = []
CB = "https://claude.ai/api/mcp/auth_callback"


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))
    print(f"  [{'OK' if ok else 'FAIL'}] {name}" + (f"  — {detail}" if detail and not ok else ""))


def text(res) -> str:
    return "".join(getattr(c, "text", "") for c in res.content)


def outside(url: str) -> None:
    print(f"\n{url}")
    hdr = {"Accept": "application/json, text/event-stream"}
    r = httpx.post(url, json={}, headers=hdr, timeout=15)
    check(r.status_code == 401, "requires authentication (401 without a token)", f"HTTP {r.status_code}")
    r = httpx.post(url, json={}, headers=hdr | {"Authorization": "Bearer wrong"}, timeout=15)
    check(r.status_code == 401, "rejects a wrong token", f"HTTP {r.status_code}")
    base = url.rsplit("/mcp", 1)[0]
    m = httpx.get(f"{base}/.well-known/oauth-authorization-server", timeout=15)
    if m.status_code == 404:
        check(False, "OAuth sign-in enabled", "no MCP_ADMIN_PASSWORD_HASH: run sudo opsgate password")
        return
    meta = m.json()
    check("registration_endpoint" in meta, "OAuth discovery published")
    # Talk to the address being tested (the metadata advertises the public one).
    issuer = str(meta.get("issuer", "")).rstrip("/")
    for k in ("registration_endpoint", "authorization_endpoint", "token_endpoint"):
        if issuer and str(meta.get(k, "")).startswith(issuer):
            meta[k] = base + meta[k][len(issuer):]
    reg = httpx.post(meta["registration_endpoint"], timeout=15, json={
        "redirect_uris": [CB], "client_name": "opsgate-doctor", "token_endpoint_auth_method": "none"})
    check(reg.status_code == 201, "Claude can register as a client", f"HTTP {reg.status_code}")
    bad = httpx.post(meta["registration_endpoint"], timeout=15, json={
        "redirect_uris": ["https://evil.example/cb"], "token_endpoint_auth_method": "none"})
    check(bad.status_code == 400, "unknown redirect addresses are refused", f"HTTP {bad.status_code}")
    if reg.status_code == 201:
        a = httpx.get(meta["authorization_endpoint"], timeout=15, params={
            "response_type": "code", "client_id": reg.json()["client_id"], "redirect_uri": CB, "state": "x",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256"})
        loc = a.headers.get("location", "")
        check(a.status_code == 302 and "/oauth/login?req=" in loc, "sign-in redirects to this server's login page",
              loc[:80])
        if loc.startswith("http"):
            if issuer and loc.startswith(issuer):
                loc = base + loc[len(issuer):]
            page = httpx.get(loc, timeout=15)
            check(page.status_code == 200 and "Allow" in page.text, "login page served", f"HTTP {page.status_code}")


async def tools(url: str, token: str) -> None:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    print(f"\nTools ({url})")
    async with streamablehttp_client(url, headers={"Authorization": f"Bearer {token}"}) as (rd, wr, _):
        async with ClientSession(rd, wr) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
            check(len(names) == 18, f"18 tools published ({len(names)})")

            async def call(name, args, want_error=False, must=None, label=None):
                res = await s.call_tool(name, args)
                t = text(res)
                ok = bool(res.isError) == want_error and (must is None or must in t)
                check(ok, label or f"{name} {args}", t[:160].replace("\n", " | "))

            await call("account_status", {}, must="Plan:", label="account_status")
            await call("list_dir", {"path": "/etc"}, must="hostname", label="list_dir /etc")
            await call("read_file", {"path": "/etc/hostname"}, label="read_file /etc/hostname")
            await call("read_file", {"path": "/etc/shadow"}, want_error=True, label="/etc/shadow is blocked")
            await call("run_command", {"command": "df -h", "cwd": "/"}, must="[rc=0]", label="run_command df -h")
            await call("run_command", {"command": "python3 -c print(1)"}, want_error=True,
                       label="interpreters are blocked")
            await call("run_command", {"command": "sudo -n -l"}, want_error=True, label="sudo is blocked")
            await call("run_command", {"command": "mv /etc /etc.x", "confirm": True}, want_error=True,
                       label="system folders are protected")
            await call("write_file", {"path": "/var/lib/opsgate/meter.json", "content": "{}", "confirm": True},
                       want_error=True, label="the agent's own files are protected")
            await call("service_status", {"name": "opsgate"}, must="active", label="service_status opsgate")
            await call("service_status", {"name": "x;id"}, want_error=True, label="invalid service names refused")
            await call("service_restart", {"name": "opsgate"}, must="NOT restarted",
                       label="restart without confirm does nothing")


def cloud() -> None:
    print("\nOpsGate Cloud")
    try:
        st = json.load(open("/var/lib/opsgate/meter.json"))
    except (OSError, ValueError):
        check(False, "usage reports", "no /var/lib/opsgate/meter.json yet (has the agent started?)")
        return
    if st.get("invalid_key"):
        check(False, "license key accepted", "rejected: run sudo opsgate license <key>")
        return
    last = st.get("last_ok")
    check(bool(last) and time.time() - last < 900, "reported to OpsGate Cloud in the last 15 minutes",
          "never" if not last else time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(last)))
    plan = (st.get("plan") or "?").capitalize()
    limit = st.get("limit")
    print(f"       plan {plan}, {st.get('used', 0):,} / {limit if limit is not None else 'unlimited'} calls this month")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--token", default=os.environ.get("MCP_TOKEN", ""))
    ap.add_argument("url", nargs="*")
    a = ap.parse_args()
    host, port = os.environ.get("MCP_HOST", "127.0.0.1"), os.environ.get("MCP_PORT", "8765")
    urls = a.url or [f"http://{host}:{port}/mcp"]
    pub = os.environ.get("MCP_PUBLIC_URL", "")
    if not a.url and pub and "example.invalid" not in pub:
        urls.append(pub.rstrip("/") + "/mcp")
    for u in urls:
        try:
            outside(u)
        except Exception as e:  # noqa: BLE001
            check(False, f"reach {u}", repr(e)[:200])
    if a.token:
        try:
            asyncio.run(asyncio.wait_for(tools(urls[0], a.token), timeout=120))
        except Exception as e:  # noqa: BLE001
            check(False, "tool calls", repr(e)[:200])
    else:
        print("\n  (tip: sudo opsgate token create doctor, then sudo opsgate doctor --token <token> to test the tools)")
    if os.path.exists("/var/lib/opsgate"):
        cloud()
    bad = [r for r in results if not r[0]]
    print(f"\nResult: {len(results) - len(bad)}/{len(results)} OK")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
