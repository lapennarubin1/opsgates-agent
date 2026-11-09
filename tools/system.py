"""systemd services, Asterisk CLI (optional) and logs."""
from __future__ import annotations

import re
import subprocess

from config import ALLOW_ALL, cfg
from security import ALLOWED_NAME_RE, resolve_inside

CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "SYSTEMD_PAGER": ""}
# Root-owned wrapper that re-validates the command (the Asterisk control socket only accepts root).
AST_WRAPPER = "/usr/local/sbin/opsgate-asterisk"
_AST_ARG = re.compile(r"^[A-Za-z0-9_.@:/+-]+$")


def _run(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout,
                              stdin=subprocess.DEVNULL, env=CLEAN_ENV)
    except FileNotFoundError:
        raise ValueError(f"Program not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        raise ValueError(f"Timed out after {timeout}s")


def _check(name: str, allowed: set[str]) -> None:
    if not ALLOWED_NAME_RE.match(name):
        raise ValueError("Service name contains invalid characters")
    if ALLOW_ALL in allowed:
        return  # no closed list (see config.py); restart/reload still require confirm=true and
                # sudo (deploy/sudoers.d) is the real closed list of what root executes.
    if name not in allowed:
        raise ValueError(f"Service not allowed: {name}. Allowed: {sorted(allowed)}")


def do_service_status(name: str) -> str:
    _check(name, cfg.services)
    active = _run(["systemctl", "is-active", name]).stdout.strip()
    detail = _run(["systemctl", "status", name, "--no-pager", "-n", "5"]).stdout
    return f"{name}: {active}\n{detail}"


def do_service_restart(name: str, confirm: bool = False) -> str:
    _check(name, cfg.restartable)
    if not confirm:
        return f"NOT restarted. Call again with confirm=true to restart {name}."
    r = _run(["sudo", "-n", "/usr/bin/systemctl", "restart", name], timeout=90)
    status = _run(["systemctl", "is-active", name]).stdout.strip()
    err = r.stderr.strip()
    hint = ""
    if r.returncode != 0 and "sudo" in err.lower():
        hint = (f"\nThis server has not authorized OpsGate to restart {name}. The owner can allow it "
                f"with: sudo opsgate-allow-restart {name}")
    return f"restart {name}: rc={r.returncode} state={status}" + (f"\n{err}" if err else "") + hint


def do_service_reload(name: str, confirm: bool = False) -> str:
    _check(name, cfg.reloadable)
    if not confirm:
        return f"NOT reloaded. Call again with confirm=true to send HUP to {name}."
    r = _run(["sudo", "-n", "/usr/bin/systemctl", "kill", "-s", "HUP", "--kill-whom=main", name])
    return f"HUP {name}: rc={r.returncode}" + (f"\n{r.stderr.strip()}" if r.stderr.strip() else "")


def validate_asterisk(command: str) -> list[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.@:/+ -]{1,200}", command.strip()):
        raise ValueError("Characters not allowed in the command")
    words = command.split(" ")
    words = [w for w in words if w]
    if not words or not all(_AST_ARG.match(w) for w in words):
        raise ValueError("Characters not allowed in the command")
    for pre in cfg.asterisk_prefixes + cfg.asterisk_change_prefixes:
        pw = pre.split()
        if words[: len(pw)] == pw:
            return words
    raise ValueError(f"Command not allowed. Allowed prefixes: {list(cfg.asterisk_prefixes + cfg.asterisk_change_prefixes)}")


def asterisk_changes_things(words: list[str]) -> bool:
    return any(words[: len(pre.split())] == pre.split() for pre in cfg.asterisk_change_prefixes)


def do_asterisk_cli(command: str, confirm: bool = False) -> str:
    words = validate_asterisk(command)
    if asterisk_changes_things(words) and not confirm:
        raise ValueError(f"'{' '.join(words)}' changes the running Asterisk: call again with confirm=true")
    r = _run(["sudo", "-n", AST_WRAPPER, " ".join(words)])
    return r.stdout or r.stderr


def tail_lines(path, n: int, block: int = 65536) -> list[str]:
    """Last n lines, reading from the end (never walks huge files from the start)."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        end = f.tell()
        data = b""
        pos = end
        while pos > 0 and data.count(b"\n") <= n:
            step = min(block, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
            if len(data) > 8_000_000:
                break
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-n:]


def do_tail_log(path: str, lines: int = 100) -> str:
    p = resolve_inside(path, cfg.log_roots)
    if not p.is_file():
        raise ValueError("Not a file")
    lines = max(1, min(lines, 1000))
    return "\n".join(tail_lines(p, lines))
