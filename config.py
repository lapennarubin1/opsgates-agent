"""OpsGate Agent configuration, read from environment variables (/etc/opsgate/env)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.1.2"


def _list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if raw is None:
        return list(default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def _paths(name: str, default: list[str]) -> list[Path]:
    return [Path(p).resolve() for p in _list(name, default)]


DEFAULT_RUN_ALLOWED = [
    "ls", "cat", "head", "tail", "grep", "wc", "du", "df", "free", "uptime", "ps",
    "stat", "file", "diff", "date", "id", "whoami", "hostname", "uname", "which",
    "find", "tree", "journalctl", "netstat", "dpkg -l", "dpkg -L",
    # Exact subcommands only, never the bare binary: a bare "python3"/"pip"/"node" would be a
    # general-purpose interpreter (equivalent to an unrestricted shell), not a read-only tool.
    "pip list", "pip show", "pip freeze", "pip3 list", "pip3 show", "pip3 freeze",
    "npm list", "npm view", "npm outdated", "node --version", "python3 --version",
    "systemctl status", "systemctl is-active", "systemctl list-units",
    "git status", "git log", "git diff", "git rev-parse", "git show", "ss",
]
DEFAULT_RUN_CONFIRM = ["git pull", "git checkout", "cp", "mv", "mkdir", "touch", "chmod", "ln"]
# Wildcard = "no closed list" for service names. Only the name format is validated and
# confirm=true is still required for anything that changes state. What root really may do is
# decided by /etc/sudoers.d/opsgate (see deploy/), which this setting does not change.
ALLOW_ALL = "*"

# Access profiles (MCP_ACCESS, comma separated; managed with `sudo opsgate access`). Every profile
# only ADDS to the read-only base, and the owner can change them at any time.
#   readonly  the base: read files, logs, services, databases (SELECT)
#   network   curl, always with confirm=true (no file output/upload, only http/https)
#   asterisk  Asterisk reload commands, always with confirm=true
#   full      a root shell (run_shell), like logging in over SSH. Owner-only, typed confirmation.
ACCESS_PROFILES = ("readonly", "network", "asterisk", "full")
ASTERISK_CHANGING = ["core reload", "dialplan reload", "pjsip reload", "module reload", "queue reload",
                     "sip reload", "voicemail reload", "manager reload", "logger reload"]


@dataclass
class Config:
    # Paths
    read_roots: list[Path] = field(default_factory=list)
    write_roots: list[Path] = field(default_factory=list)
    log_roots: list[Path] = field(default_factory=list)
    backup_dir: Path = Path("/var/backups/opsgate")
    audit_file: Path = Path("/var/log/opsgate/audit.jsonl")
    deny_names: list[str] = field(default_factory=list)
    # Closed lists
    services: set[str] = field(default_factory=set)
    restartable: set[str] = field(default_factory=set)
    reloadable: set[str] = field(default_factory=set)
    asterisk_prefixes: tuple[str, ...] = ()
    asterisk_change_prefixes: tuple[str, ...] = ()   # reload commands (profile "asterisk"), need confirm
    access: tuple[str, ...] = ("readonly",)
    full_access: bool = False                         # profile "full": run_shell is available
    shell_timeout_max: int = 900
    run_allowed: list[str] = field(default_factory=list)
    run_confirm: list[str] = field(default_factory=list)
    # Limits
    max_output_chars: int = 20000
    max_write_bytes: int = 1_000_000
    max_read_bytes: int = 2_000_000
    run_timeout_max: int = 120
    rate_per_minute: int = 60
    max_sessions: int = 5
    session_ttl: int = 1800
    # Database (READ-ONLY user)
    db_host: str = "127.0.0.1"
    db_port: int = 3306
    db_user: str = ""
    db_password: str = ""
    db_name: str = ""
    db_max_rows: int = 200
    # Auth / network
    token_sha256: list[str] = field(default_factory=list)
    public_url: str = "https://mcp.example.invalid"
    allowed_hosts: list[str] = field(default_factory=list)
    # Built-in OAuth login (claude.ai / ChatGPT). Empty = static token only.
    admin_password_hash: str = ""
    totp_secret: str = ""                  # optional two-step verification for the login page
    state_dir: Path = Path("/var/lib/opsgate")
    oauth_redirect_hosts: list[str] = field(default_factory=list)
    host: str = "127.0.0.1"
    port: int = 8765
    # Licensing / usage metering (OpsGate Cloud). Only call COUNTS are ever sent, never content.
    license_key: str = ""
    cloud_url: str = ""
    metering: bool = True
    offline_grace_hours: int = 72

    @classmethod
    def from_env(cls) -> "Config":
        e = os.environ.get
        # Whole filesystem by default: this is a general-purpose agent, not a per-project one.
        # Set MCP_READ_ROOTS / MCP_WRITE_ROOTS to scope it to specific folders.
        base_roots = ["/"]
        access = tuple(a for a in _list("MCP_ACCESS", ["readonly"]) if a in ACCESS_PROFILES) or ("readonly",)
        extra_confirm = ["curl"] if "network" in access else []
        return cls(
            read_roots=_paths("MCP_READ_ROOTS", base_roots),
            write_roots=_paths("MCP_WRITE_ROOTS", base_roots),
            log_roots=_paths("MCP_LOG_ROOTS", ["/var/log"]),
            backup_dir=Path(e("MCP_BACKUP_DIR", "/var/backups/opsgate")),
            audit_file=Path(e("MCP_AUDIT_FILE", "/var/log/opsgate/audit.jsonl")),
            deny_names=_list("MCP_DENY_NAMES", [
                ".env", ".env.*", "*.pem", "*.key", "*.p12", "id_rsa*", "id_ed25519*",
                "device.json", "*.kdbx", "authorized_keys", "shadow", "gshadow", "oauth.db*", "environ", "env",
            ]),
            services=set(_list("MCP_SERVICES", [ALLOW_ALL])),
            restartable=set(_list("MCP_RESTARTABLE", [ALLOW_ALL])),
            reloadable=set(_list("MCP_RELOADABLE", [ALLOW_ALL])),
            asterisk_prefixes=tuple(_list("MCP_ASTERISK_PREFIXES", [
                "pjsip show", "core show channels", "core show calls", "core show uptime",
                "core show version", "dialplan show", "sip show peers"])),
            run_allowed=_list("MCP_RUN_ALLOWED", DEFAULT_RUN_ALLOWED),
            run_confirm=_list("MCP_RUN_CONFIRM", DEFAULT_RUN_CONFIRM)
            + [c for c in extra_confirm if c not in _list("MCP_RUN_CONFIRM", DEFAULT_RUN_CONFIRM)],
            asterisk_change_prefixes=tuple(ASTERISK_CHANGING) if "asterisk" in access else (),
            access=access,
            full_access="full" in access,
            shell_timeout_max=int(e("MCP_SHELL_TIMEOUT_MAX", "900")),
            max_output_chars=int(e("MCP_MAX_OUTPUT", "20000")),
            run_timeout_max=int(e("MCP_RUN_TIMEOUT_MAX", "120")),
            rate_per_minute=int(e("MCP_RATE_PER_MIN", "120")),
            db_host=e("MCP_DB_HOST", "127.0.0.1"),
            db_port=int(e("MCP_DB_PORT", "3306")),
            db_user=e("MCP_DB_USER", ""),
            db_password=e("MCP_DB_PASSWORD", ""),
            db_name=e("MCP_DB_NAME", ""),
            token_sha256=[h.lower() for h in _list("MCP_TOKEN_SHA256", [])],
            public_url=e("MCP_PUBLIC_URL", "https://mcp.example.invalid"),
            allowed_hosts=_list("MCP_ALLOWED_HOSTS", []),
            admin_password_hash=e("MCP_ADMIN_PASSWORD_HASH", ""),
            totp_secret=e("MCP_TOTP_SECRET", ""),
            state_dir=Path(e("MCP_STATE_DIR", "/var/lib/opsgate")),
            oauth_redirect_hosts=_list("MCP_OAUTH_REDIRECT_HOSTS", []),
            host=e("MCP_HOST", "127.0.0.1"),
            port=int(e("MCP_PORT", "8765")),
            license_key=e("OPSGATE_LICENSE_KEY", ""),
            cloud_url=e("OPSGATE_CLOUD_URL", "").rstrip("/"),
            metering=e("OPSGATE_METERING", "on").lower() not in ("off", "0", "false", "no"),
            offline_grace_hours=int(e("OPSGATE_OFFLINE_GRACE_HOURS", "72")),
        )


cfg = Config.from_env()
