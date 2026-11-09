#!/usr/bin/env python3
"""Read and update /etc/opsgate/env safely (KEY=VALUE lines, no shell evaluation).

    envfile.py FILE get KEY
    envfile.py FILE set KEY=VALUE [KEY=VALUE ...]
    envfile.py FILE unset KEY [KEY ...]
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def read(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


def get(lines: list[str], key: str) -> str | None:
    for line in lines:
        if line.startswith(key + "="):
            return line[len(key) + 1:]
    return None


def write(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".env.")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines).rstrip("\n") + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def set_values(lines: list[str], pairs: dict[str, str]) -> list[str]:
    out, done = [], set()
    for line in lines:
        k = line.split("=", 1)[0]
        if k in pairs:
            if k not in done:
                out.append(f"{k}={pairs[k]}")
                done.add(k)
            continue
        out.append(line)
    out += [f"{k}={v}" for k, v in pairs.items() if k not in done]
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    path, cmd, args = Path(argv[0]), argv[1], argv[2:]
    lines = read(path)
    if cmd == "get":
        v = get(lines, args[0])
        if v is None:
            return 1
        print(v)
        return 0
    if cmd == "set":
        pairs = {}
        for a in args:
            k, sep, v = a.partition("=")
            if not sep or not KEY_RE.match(k) or "\n" in v or "\r" in v:
                print(f"invalid assignment: {k}", file=sys.stderr)
                return 2
            pairs[k] = v
        write(path, set_values(lines, pairs))
        return 0
    if cmd == "unset":
        write(path, [line for line in lines if line.split("=", 1)[0] not in args])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
