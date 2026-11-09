#!/usr/bin/env python3
"""Add or remove the agent's HTTPS route in EasyPanel's Traefik (custom.yaml), keeping every other
route in the file untouched. A backup is written next to the file before any change.

    proxy_route.py add    --file /etc/easypanel/traefik/config/custom.yaml --name opsgate \
                          --domain mcp.example.com --upstream http://172.18.0.1:8765
    proxy_route.py remove --file ... --name opsgate
"""
import argparse
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import yaml

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
HEADER = "# Routers/services named opsgate* are managed by OpsGate (backups: custom.yaml.bak-*). Other entries are yours.\n"


def load(path: Path) -> dict:
    if not path.exists() or not path.read_text().strip():
        return {}
    data = yaml.safe_load(path.read_text())
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise SystemExit(f"{path} is not a YAML mapping; not touching it")
    return data


def save(path: Path, data: dict) -> None:
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.bak-{time.strftime('%Y%m%d%H%M%S')}"))
    text = HEADER + yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".custom.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["add", "remove"])
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default="opsgate")
    ap.add_argument("--domain")
    ap.add_argument("--upstream")
    ap.add_argument("--resolver", default="letsencrypt")
    a = ap.parse_args()
    path = Path(a.file)
    data = load(path)
    http = data.setdefault("http", {}) or {}
    data["http"] = http
    routers = http.setdefault("routers", {}) or {}
    services = http.setdefault("services", {}) or {}
    http["routers"], http["services"] = routers, services
    if a.action == "remove":
        changed = routers.pop(a.name, None) is not None
        changed = services.pop(a.name, None) is not None or changed
        if changed:
            save(path, data)
        return 0
    if not a.domain or not DOMAIN_RE.match(a.domain):
        raise SystemExit(f"invalid domain: {a.domain}")
    if not a.upstream or not re.match(r"^http://[0-9.]+:\d{2,5}$", a.upstream):
        raise SystemExit(f"invalid upstream: {a.upstream}")
    want_router = {"rule": f"Host(`{a.domain}`)", "entryPoints": ["https"], "service": a.name,
                   "tls": {"certResolver": a.resolver, "domains": [{"main": a.domain}]}}
    want_service = {"loadBalancer": {"passHostHeader": True, "servers": [{"url": a.upstream}]}}
    if routers.get(a.name) == want_router and services.get(a.name) == want_service:
        return 0  # already as wanted
    routers[a.name] = want_router
    services[a.name] = want_service
    save(path, data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
