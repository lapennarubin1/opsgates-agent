"""run_command and process sessions. ALLOW-list by prefix, no shell.

Every argument (and every value glued to an option: -fPATH, --opt=PATH) is treated as a possible
path: it is resolved against cwd (following symlinks) and must stay inside the allowed folders.
Protected names (.env, keys...) are refused even without a path.

Known limit: this is not a sandbox. The real containment is the unprivileged user + systemd."""
from __future__ import annotations

import os
import re
import shlex
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path

from config import cfg
from security import SYSTEM_ROOTS, check_readable, check_writable, is_denied_name

CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "SYSTEMD_PAGER": "", "PAGER": "cat"}

# Forbidden options per program (token prefixes). Covers recursion that would bypass the protected
# file list, and options that execute, write or reach another machine.
_FORBIDDEN_LONG = {
    "grep": ("--recursive", "--dereference-recursive", "--directories", "--devices"),
    "diff": ("--recursive", "--from-file", "--to-file"),
    "git": ("--output", "--ext-diff", "--textconv", "--exec", "--upload-pack", "--receive-pack",
            "--config", "--git-dir", "--work-tree", "--open-files-in-pager", "--paginate"),
    "systemctl": ("--host", "--machine"),
    "journalctl": ("--host", "--machine", "--merge", "--vacuum", "--rotate", "--flush", "--relinquish"),
    "date": ("--set",),
    "ss": ("--kill",),
}
_FORBIDDEN_SHORT = {  # forbidden letters inside short option groups (-rn, -Rl...)
    "grep": "rRd",
    "diff": "r",
    "systemctl": "HM",
    "journalctl": "HM",
    "date": "s",
    "ss": "K",
}
# Whole arguments that are never allowed, wherever they appear (even after "--"). find's actions
# run programs, delete or write files; tree -o/-R and file -C write files.
_FORBIDDEN_WORDS = {
    "find": {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"},
}
# curl (profile "network"): no output files, uploads, config files, client certs, proxies or
# anything that is not plain http(s). Bodies may be given with -d/--data/--json (never @file).
_FORBIDDEN_LONG["curl"] = ("--output", "--remote-name", "--remote-header-name", "--config", "--upload-file",
                           "--form", "--cookie-jar", "--netrc", "--trace", "--dump-header", "--libcurl",
                           "--hsts", "--alt-svc", "--unix-socket", "--proxy", "--create-dirs", "--next",
                           "--cert", "--key", "--cacert", "--capath", "--parallel", "--variable",
                           "--etag", "--stderr", "--output-dir", "--ftp", "--use-ascii", "--proto")
_FORBIDDEN_SHORT["curl"] = "oOKTFcDJxEZ"
_FORBIDDEN_SHORT.update({"tree": "oR", "file": "Cm"})
_FORBIDDEN_LONG.update({"tree": ("--output", "--fromfile"), "file": ("--compile", "--magic-file")})
_MODIFYING = {"cp", "mv", "mkdir", "touch", "chmod", "ln"}
# For these, a system directory (/etc, /var...) can never be the DIRECT target
# (renaming it, changing its permissions...). See security.SYSTEM_ROOTS.
_TARGETS_WHOLE_PATH = {"mv", "chmod", "ln"}


def _prefix_match(tokens: list[str], prefixes: list[str]) -> int:
    """Length of the matching allowed prefix (0 if none)."""
    best = 0
    for pre in prefixes:
        pt = pre.split()
        if tokens[: len(pt)] == pt:
            best = max(best, len(pt))
    return best


def _within(p: Path, roots: list[Path]) -> bool:
    return any(p == r or r in p.parents for r in roots)


def _candidates(tok: str) -> list[str]:
    if tok.startswith("--"):
        return [tok.split("=", 1)[1]] if "=" in tok else []
    if tok.startswith("-") and len(tok) > 1:
        return [tok[2:]] if len(tok) > 2 else []  # -fVALUE: the glued value may be a path
    return [tok]


def _check_options(prog: str, args: list[str]) -> None:
    words = _FORBIDDEN_WORDS.get(prog, set())
    for a in args:
        if a in words:
            raise ValueError(f"Option not allowed for {prog}: {a} (it runs programs or modifies files)")
        if prog == "ps" and not a.startswith("-") and "e" in a:
            raise ValueError("Option not allowed for ps: BSD-style 'e' (it prints process environments)")
    for a in args:
        if a == "--":
            break
        if a.startswith("--"):
            if a.startswith(_FORBIDDEN_LONG.get(prog, ())):
                raise ValueError(f"Option not allowed for {prog}: {a.split('=')[0]}")
        elif a.startswith("-") and len(a) > 1:
            bad = set(a[1:]) & set(_FORBIDDEN_SHORT.get(prog, ""))
            if bad:
                raise ValueError(f"Option not allowed for {prog}: -{''.join(sorted(bad))}"
                                 + (" (use search_files to search folders)" if prog == "grep" else ""))


_CURL_FILE_ARG = re.compile(r"^-{1,2}[A-Za-z-]*=?@")


def _check_curl(args: list[str]) -> None:
    prev = ""
    for a in args:
        if a.startswith("@") or _CURL_FILE_ARG.match(a):
            raise ValueError("curl: reading a body from a file (@file) is not allowed; pass the text itself")
        if (prev == "--data-urlencode" or a.startswith("--data-urlencode=")) and "@" in a.split("=", 1)[-1]:
            raise ValueError("curl: --data-urlencode with a file is not allowed")
        prev = a


def _confine_args(prog: str, args: list[str], work: Path) -> None:
    modifying = prog in _MODIFYING
    roots = cfg.write_roots if modifying else cfg.read_roots + cfg.log_roots
    for a in args:
        for cand in _candidates(a):
            if not cand:
                continue
            if cand.startswith("~"):
                raise ValueError("'~' is not allowed")
            if is_denied_name(Path(cand)):
                raise ValueError(f"Protected file (secrets/keys): {Path(cand).name}")
            p = Path(cand) if cand.startswith("/") else work / cand
            looks_like_path = "/" in cand or cand in (".", "..") or os.path.lexists(p)
            if not looks_like_path:
                continue
            rp = p.resolve()
            if not _within(rp, roots):
                raise ValueError(f"Path outside the allowed folders: {rp}")
            if is_denied_name(rp):
                raise ValueError(f"Protected file (secrets/keys): {rp.name}")
            check_readable(rp)
            if modifying:
                check_writable(rp)
            if modifying and ".git" in rp.parts:
                raise ValueError("Modifying inside .git is not allowed")
            if prog in _TARGETS_WHOLE_PATH and rp in SYSTEM_ROOTS:
                raise ValueError(f"Modifying the system directory {rp} itself is not allowed")


# Repository settings that make git run a program (filters on checkout/status, merge drivers,
# ssh/credential/askpass helpers, upload-pack, includes of other config files...). A repo whose own
# .git/config sets any of them is refused: the AI cannot write .git, but a repo on the server can.
_GIT_DANGEROUS = re.compile(
    r"^(?:filter\..+\.(?:clean|smudge|process)|merge\..+\.driver|diff\..+\.(?:command|textconv)"
    r"|core\.(?:sshcommand|gitproxy|askpass|fsmonitor|hookspath|pager|editor|attributesfile|alternaterefscommand)"
    r"|credential\..*|remote\..+\.(?:uploadpack|receivepack|vcs)|url\..+\.(?:insteadof|pushinsteadof)"
    r"|include\..*|includeif\..*|protocol\..*|uploadpack\..*|sequence\.editor|gpg\..*program"
    r"|submodule\..+\.update)$", re.I)
_GIT_SAFE_VALUES = re.compile(r"^git-lfs (?:clean|smudge|filter-process)\b")  # standard Git LFS filters


def _check_git_repo(work: Path) -> None:
    """Every config source the real git command will read (system/global are off in CLEAN_ENV;
    local, worktree and included files are listed here, whoever owns the repository)."""
    try:
        r = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(work), "config", "--list", "--includes"],
                           capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL, env=CLEAN_ENV)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Could not inspect this repository's git configuration; git was not run.")
    if r.returncode != 0:
        if "not a git repository" in (r.stderr or "").lower():
            return  # git itself will report it; nothing repository-defined can run
        raise ValueError("Could not inspect this repository's git configuration; git was not run.")
    for line in r.stdout.splitlines():
        name, _, value = line.partition("=")
        if _GIT_DANGEROUS.match(name) and not (name.lower().startswith("filter.lfs.") and _GIT_SAFE_VALUES.match(value)):
            raise ValueError(f"This repository's own git config sets '{name}', which makes git run a program. "
                             "For safety OpsGate does not run git here; run it yourself on the server.")


def _prepare(command: str, cwd: str | None, confirm: bool) -> tuple[list[str], str]:
    if not command.strip():
        raise ValueError("Empty command")
    try:
        tokens = shlex.split(command)
    except ValueError as e:
        raise ValueError(f"Malformed command: {e}")
    allowed = cfg.run_allowed + cfg.run_confirm
    if not _prefix_match(tokens, allowed):
        raise ValueError("Command not allowed. Allowed (prefixes): " + ", ".join(sorted(allowed)))
    if _prefix_match(tokens, cfg.run_confirm) and not confirm:
        raise ValueError("This command changes things: call again with confirm=true")
    if cwd:
        if not cwd.startswith("/"):
            raise ValueError("cwd must be absolute")
        work = Path(cwd).resolve()
        if not _within(work, cfg.read_roots):
            raise ValueError(f"cwd outside the allowed folders: {work}")
    else:
        work = cfg.read_roots[0]
    if not work.is_dir():
        raise ValueError("cwd is not a directory")
    prog = tokens[0]
    _check_options(prog, tokens[1:])
    if prog == "curl":  # URLs look like paths: curl has its own checks instead of folder confinement
        _check_curl(tokens[1:])
        tokens = ["curl", "-q", "--proto", "=http,https", "--proto-redir", "=http,https"] + tokens[1:]
    else:
        _confine_args(prog, tokens[1:], work)
    if prog == "git":  # no pager, hooks or fsmonitor even if the repo configures them
        _check_git_repo(work)
        rest = tokens[1:]
        if rest and rest[0] in ("diff", "log", "show"):  # repo-defined diff drivers never run
            rest = [rest[0], "--no-ext-diff", "--no-textconv"] + rest[1:]
        if rest and rest[0] in ("pull", "checkout"):
            bad = [a for a in rest[1:] if a.startswith(("--rebase", "--no-ff", "--strategy", "--recurse-submodules",
                                                         "--upload-pack", "-s", "-X", "-r"))]
            if bad:
                raise ValueError(f"Option not allowed for git {rest[0]}: {bad[0]}")
            if rest[0] == "pull" and "--ff-only" not in rest:
                rest = ["pull", "--ff-only"] + rest[1:]  # never a merge (no merge drivers)
        tokens = ["git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                  "-c", "diff.external=", "-c", "safe.directory=*", "-c", "protocol.ext.allow=never",
                  "-c", "submodule.recurse=false"] + rest
    return tokens, str(work)


def do_run_command(command: str, cwd: str | None = None, timeout: int = 30, confirm: bool = False) -> str:
    tokens, work = _prepare(command, cwd, confirm)
    timeout = max(1, min(timeout, cfg.run_timeout_max))
    try:
        r = subprocess.run(tokens, cwd=work, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL, env=CLEAN_ENV)
    except subprocess.TimeoutExpired:
        raise ValueError(f"Timed out after {timeout}s; use start_session for long-running processes")
    except FileNotFoundError:
        raise ValueError(f"Program not found: {tokens[0]}")
    out = r.stdout + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
    return f"[rc={r.returncode}]\n{out}"


# ------------------------------------------------------------------ sessions
class _Session:
    def __init__(self, tokens: list[str], cwd: str, label: str | None = None, env: dict | None = None):
        self.id = uuid.uuid4().hex[:8]
        self.cmd = label or " ".join(tokens)
        self.started = time.time()
        self.buf = ""
        self.read_pos = 0
        self.lock = threading.Lock()
        self.proc = subprocess.Popen(tokens, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, text=True, errors="replace", env=env or CLEAN_ENV,
                                     start_new_session=True)
        threading.Thread(target=self._pump, daemon=True).start()
        timer = threading.Timer(cfg.session_ttl, self.kill)
        timer.daemon = True  # otherwise the process cannot exit until the TTL expires
        timer.start()

    def _pump(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            with self.lock:
                self.buf += line
                if len(self.buf) > 400_000:  # memory cap
                    drop = len(self.buf) - 400_000
                    self.buf = self.buf[drop:]
                    self.read_pos = max(0, self.read_pos - drop)

    def kill(self) -> None:
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    def read_new(self) -> str:
        with self.lock:
            out = self.buf[self.read_pos:]
            self.read_pos = len(self.buf)
        return out


_sessions: dict[str, _Session] = {}
_sessions_lock = threading.Lock()


def do_start_session(command: str, cwd: str | None = None, confirm: bool = False) -> str:
    tokens, work = _prepare(command, cwd, confirm)
    with _sessions_lock:
        for sid in [k for k, s in _sessions.items() if s.proc.poll() is not None and s.read_pos >= len(s.buf)]:
            _sessions.pop(sid)
        if len(_sessions) >= cfg.max_sessions:
            raise ValueError(f"At most {cfg.max_sessions} active sessions; close one with stop_session")
        try:
            s = _Session(tokens, work)
        except FileNotFoundError:
            raise ValueError(f"Program not found: {tokens[0]}")
        _sessions[s.id] = s
    return f"Session {s.id} started: {command} (auto-closes after {cfg.session_ttl}s)"


def do_read_session(session_id: str, wait: float = 2.0) -> str:
    s = _sessions.get(session_id)
    if not s:
        raise ValueError("No such session")
    time.sleep(max(0.0, min(wait, 10.0)))
    rc = s.proc.poll()
    state = "running" if rc is None else f"finished rc={rc}"
    return f"[{state}]\n{s.read_new()}"


def do_stop_session(session_id: str) -> str:
    s = _sessions.get(session_id)
    if not s:
        raise ValueError("No such session")
    s.kill()
    return f"Session {session_id} stopped"


def do_list_sessions() -> str:
    with _sessions_lock:
        items = list(_sessions.values())
    if not items:
        return "(no sessions)"
    return "\n".join(
        f"{s.id}  {'active' if s.proc.poll() is None else 'finished'}  {int(time.time() - s.started)}s  {s.cmd}"
        for s in items)


# ------------------------------------------------------------------ full access (profile "full")
SHELL_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
             "HOME": "/root", "TERM": "dumb", "PAGER": "cat", "SYSTEMD_PAGER": "", "GIT_TERMINAL_PROMPT": "0"}


def _shell_prepare(command: str, cwd: str | None) -> tuple[list[str], str]:
    if not cfg.full_access:
        raise ValueError("Full access is not enabled on this server. The owner can turn it on with: sudo opsgate access")
    if not command.strip():
        raise ValueError("Empty command")
    work = cwd or "/"
    if not work.startswith("/") or not Path(work).is_dir():
        raise ValueError("cwd must be an existing absolute directory")
    return ["sudo", "-n", "--", "/bin/bash", "-c", command], work


def do_run_shell(command: str, cwd: str | None = None, timeout: int = 60) -> str:
    argv, work = _shell_prepare(command, cwd)
    timeout = max(1, min(timeout, cfg.shell_timeout_max))
    try:
        r = subprocess.run(argv, cwd=work, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL, env=SHELL_ENV)
    except subprocess.TimeoutExpired:
        raise ValueError(f"Timed out after {timeout}s; run it in the background (background=true) and use read_session")
    out = r.stdout + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
    return f"[rc={r.returncode}]\n{out}"


def do_start_shell(command: str, cwd: str | None = None) -> str:
    argv, work = _shell_prepare(command, cwd)
    with _sessions_lock:
        for sid in [k for k, x in _sessions.items() if x.proc.poll() is not None and x.read_pos >= len(x.buf)]:
            _sessions.pop(sid)
        if len(_sessions) >= cfg.max_sessions:
            raise ValueError(f"At most {cfg.max_sessions} active sessions; close one with stop_session")
        sess = _Session(argv, work, label="shell: " + command[:80], env=SHELL_ENV)
        _sessions[sess.id] = sess
    return f"Session {sess.id} started in the background (read it with read_session; auto-closes after {cfg.session_ttl}s)"
