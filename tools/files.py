"""File tools: read, search, and write with backup and confirmation."""
from __future__ import annotations

import difflib
import os
import re
import shutil
import time
from pathlib import Path

from config import cfg
from security import agent_private, check_writable, has_redaction_marker, is_denied_name, resolve_inside


def _within(p: Path, roots: list[Path]) -> bool:
    return any(p == r or r in p.parents for r in roots)


def do_list_dir(path: str, depth: int = 1) -> str:
    root = resolve_inside(path, cfg.read_roots, allow_denied=True)
    if not root.is_dir():
        raise ValueError("Not a directory")
    depth = max(1, min(depth, 4))
    lines: list[str] = []
    private = agent_private()

    def walk(d: Path, level: int) -> None:
        try:
            entries = sorted(d.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        except PermissionError:
            lines.append("  " * level + "[permission denied]")
            return
        for e in entries:
            if len(lines) > 2000:
                lines.append("...[listing truncated]")
                return
            if is_denied_name(e) or _within(e.resolve(), private):
                lines.append("  " * level + f"{e.name}  [protected]")
            elif e.is_symlink():
                lines.append("  " * level + f"{e.name} -> (symlink)")
            elif e.is_dir():
                lines.append("  " * level + f"{e.name}/")
                if level + 1 < depth:
                    walk(e, level + 1)
            else:
                try:
                    lines.append("  " * level + f"{e.name}  ({e.stat().st_size} B)")
                except OSError:
                    lines.append("  " * level + f"{e.name}  (?)")

    walk(root, 0)
    return "\n".join(lines) or "(empty)"


def do_read_file(path: str, offset: int = 0, max_lines: int = 300) -> str:
    p = resolve_inside(path, cfg.read_roots)
    if not p.is_file():
        raise ValueError("Not a file")
    if p.stat().st_size > cfg.max_read_bytes:
        raise ValueError(f"File too large (> {cfg.max_read_bytes} B); use search_files or tail_log")
    lines = p.read_text(errors="replace").splitlines()
    total = len(lines)
    offset = max(0, offset)
    max_lines = max(1, min(max_lines, 2000))
    chunk = lines[offset: offset + max_lines]
    head = f"# {p}  (lines {offset + 1}-{offset + len(chunk)} of {total})\n"
    return head + "\n".join(f"{offset + i + 1}\t{l}" for i, l in enumerate(chunk))


def do_search_files(pattern: str, path: str, glob: str = "*", max_results: int = 100) -> str:
    root = resolve_inside(path, cfg.read_roots, allow_denied=True)
    if ".." in Path(glob).parts or glob.startswith("/"):
        raise ValueError("glob cannot contain '..' or start with '/'")
    if len(pattern) > 500:
        raise ValueError("Pattern too long")
    try:
        rx = re.compile(pattern)
    except re.error as e:
        raise ValueError(f"Invalid regular expression: {e}")
    max_results = max(1, min(max_results, 500))
    hits: list[str] = []
    private = agent_private()
    files = [root] if root.is_file() else root.rglob(glob)
    scanned = 0
    for f in files:
        if len(hits) >= max_results or scanned > 5000:
            break
        try:
            if f.is_symlink() or not f.is_file() or is_denied_name(f) or ".git" in f.parts:
                continue
            rf = f.resolve()
            if not _within(rf, cfg.read_roots) or _within(rf, private) or f.stat().st_size > cfg.max_read_bytes:
                continue
            scanned += 1
            for n, line in enumerate(rf.read_text(errors="ignore").splitlines(), 1):
                if rx.search(line[:5000]):  # per-line cap: avoids slow regexes on huge lines
                    hits.append(f"{rf}:{n}: {line[:300]}")
                    if len(hits) >= max_results:
                        break
        except (PermissionError, OSError):
            continue
    return "\n".join(hits) or "(no matches)"


# ------------------------------------------------------------ writing
def _diff(old: str, new: str, name: str) -> str:
    d = difflib.unified_diff(old.splitlines(), new.splitlines(),
                             f"{name} (current)", f"{name} (new)", lineterm="")
    return "\n".join(d) or "(no changes)"


def do_backup(p: Path) -> Path:
    cfg.backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1_000_000_000:09d}"
    dest = cfg.backup_dir / f"{stamp}__{str(p).strip('/').replace('/', '__')}"
    shutil.copy2(p, dest)
    return dest


def _check_write_target(p: Path) -> None:
    if ".git" in p.parts:
        raise ValueError("Writing inside .git is not allowed")


def _refuse_redacted(text: str) -> None:
    if has_redaction_marker(text):
        raise ValueError(
            "The content contains hidden secrets (***). Writing it would destroy the real passwords. "
            "Use edit_file to change only the lines you need.")


def _commit(p: Path, new: str, existed: bool) -> str:
    if len(new.encode()) > cfg.max_write_bytes:
        raise ValueError("Content too large")
    target = p if existed else p.parent
    if not os.access(target, os.W_OK):  # before the backup: if it cannot be written, no orphan copy is left
        raise ValueError(f"No write permission on {target}. The server owner can allow it with: "
                         f"sudo opsgate allow-write {target if target.is_dir() else target.parent}")
    bk = do_backup(p) if existed else None
    # Write over the same file to keep owner and permissions.
    with open(p, "w", encoding="utf-8") as f:
        f.write(new)
        f.flush()
        os.fsync(f.fileno())
    return f"Wrote {p}" + (f"\nBackup: {bk}" if bk else "\n(new file, no backup)")


def do_write_file(path: str, content: str, confirm: bool = False) -> str:
    p = resolve_inside(path, cfg.write_roots)
    check_writable(p)
    _check_write_target(p)
    _refuse_redacted(content)
    existed = p.exists()
    if existed and not p.is_file():
        raise ValueError("The target is not a file")
    if not p.parent.is_dir():
        raise ValueError("The parent directory does not exist")
    old = p.read_text(errors="replace") if existed else ""
    if not confirm:
        return ("NOT written. Preview of the change; call again with confirm=true to apply it.\n"
                + _diff(old, content, p.name))
    return _commit(p, content, existed)


def do_edit_file(path: str, old: str, new: str, confirm: bool = False) -> str:
    p = resolve_inside(path, cfg.write_roots)
    check_writable(p)
    _check_write_target(p)
    if not p.is_file():
        raise ValueError("The file does not exist")
    if not old:
        raise ValueError("'old' cannot be empty")
    _refuse_redacted(new)
    text = p.read_text(errors="replace")
    n = text.count(old)
    if n == 0:
        raise ValueError("The text to replace was not found")
    if n > 1:
        raise ValueError(f"The text appears {n} times; add context so it is unique")
    updated = text.replace(old, new, 1)
    if not confirm:
        return ("NOT written. Preview; call again with confirm=true to apply it.\n"
                + _diff(text, updated, p.name))
    return _commit(p, updated, True)


def do_backup_create(path: str) -> str:
    p = resolve_inside(path, cfg.read_roots)
    if not p.is_file():
        raise ValueError("Not a file")
    return f"Backup created: {do_backup(p)}"
