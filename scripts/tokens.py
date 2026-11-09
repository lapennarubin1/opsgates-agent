#!/usr/bin/env python3
"""Static access tokens for clients without a browser sign-in (scripts, Codex, CI...).
Only SHA-256 hashes are stored: names in /etc/opsgate/tokens.json, hashes in MCP_TOKEN_SHA256.

    tokens.py --env ENV --db DB create NAME     prints the token once
    tokens.py --env ENV --db DB list
    tokens.py --env ENV --db DB revoke NAME
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import envfile  # noqa: E402

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")


def load(db: Path) -> list[dict]:
    try:
        data = json.loads(db.read_text())
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save(db: Path, items: list[dict], env: Path) -> None:
    db.write_text(json.dumps(items, indent=1))
    os.chmod(db, 0o600)
    hashes = ",".join(t["sha256"] for t in items)
    lines = envfile.read(env)
    envfile.write(env, envfile.set_values(lines, {"MCP_TOKEN_SHA256": hashes}))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("cmd", choices=["create", "list", "revoke"])
    ap.add_argument("name", nargs="?")
    a = ap.parse_args()
    env, db = Path(a.env), Path(a.db)
    items = load(db)
    if a.cmd == "list":
        if not items:
            print("No static tokens. Create one with: sudo opsgate token create NAME")
        for t in items:
            print(f"{t['name']:<24} created {time.strftime('%Y-%m-%d', time.gmtime(t['created']))}  "
                  f"sha256 {t['sha256'][:12]}…")
        return 0
    if not a.name or not NAME_RE.match(a.name):
        print("Give the token a short name (letters, digits, . _ -), e.g. my-laptop", file=sys.stderr)
        return 2
    if a.cmd == "create":
        if any(t["name"] == a.name for t in items):
            print(f"A token named {a.name} already exists. Revoke it first or pick another name.", file=sys.stderr)
            return 1
        token = "ogt_" + secrets.token_urlsafe(32)
        items.append({"name": a.name, "sha256": hashlib.sha256(token.encode()).hexdigest(), "created": time.time()})
        save(db, items, env)
        print(token)
        return 0
    left = [t for t in items if t["name"] != a.name]
    if len(left) == len(items):
        print(f"No token named {a.name}", file=sys.stderr)
        return 1
    save(db, left, env)
    return 0


if __name__ == "__main__":
    sys.exit(main())
