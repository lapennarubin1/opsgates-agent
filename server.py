"""OpsGate Agent: a secure, self-hosted MCP server that lets AI assistants operate a server."""
from __future__ import annotations

import sys
import time

from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from auth import StaticTokenVerifier
from config import VERSION, cfg
from oauth import SCOPE, LocalOAuthProvider
from security import guard
from tools import commands, db, files, system

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
SESSION = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
# run_command/start_session can change things (cp, mv, git pull) with confirm=true: marked destructive.
CMD = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

INSTRUCTIONS = (
    "OpsGate gives you controlled access to this server. Reading is free within the allowed paths. "
    "Anything that changes state (writing files, modifying commands, restarting services) first "
    "returns a preview and only runs when called again with confirm=true: always show the preview to "
    "the user and ask before confirming. Secrets are hidden as *** in outputs; never write *** back "
    "into a file (use edit_file on the specific lines instead).")


def build() -> FastMCP:
    hosts = cfg.allowed_hosts or [f"{cfg.host}:{cfg.port}", "127.0.0.1:*", "localhost:*"]
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts,
        allowed_origins=["https://claude.ai", "https://chatgpt.com"])
    common = dict(instructions=INSTRUCTIONS, host=cfg.host, port=cfg.port,
                  transport_security=security, stateless_http=False)
    if cfg.admin_password_hash:
        # Built-in OAuth login (claude.ai, ChatGPT...) + static tokens for Claude Code / Codex / scripts.
        resource = cfg.public_url.rstrip("/") + "/mcp"
        provider = LocalOAuthProvider(cfg.state_dir / "oauth.db", cfg.public_url, resource,
                                      cfg.admin_password_hash, cfg.token_sha256, cfg.oauth_redirect_hosts or None,
                                      cfg.totp_secret)
        mcp = FastMCP("opsgate", auth_server_provider=provider, auth=AuthSettings(
            issuer_url=cfg.public_url, resource_server_url=resource, validate_token_resource=True,
            client_registration_options=ClientRegistrationOptions(
                enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]),
            revocation_options=RevocationOptions(enabled=True), required_scopes=[SCOPE]), **common)
        mcp.custom_route("/oauth/login", methods=["GET", "POST"])(provider.login_page)
    else:
        mcp = FastMCP("opsgate", token_verifier=StaticTokenVerifier(cfg.token_sha256),
                      auth=AuthSettings(issuer_url=cfg.public_url, resource_server_url=cfg.public_url,
                                        validate_token_resource=False), **common)

    @mcp.tool(annotations=RO)
    @guard("list_dir")
    def list_dir(path: str, depth: int = 1) -> str:
        """List an allowed directory (depth 1-4). Protected files are shown but marked [protected]."""
        return files.do_list_dir(path, depth)

    @mcp.tool(annotations=RO)
    @guard("read_file")
    def read_file(path: str, offset: int = 0, max_lines: int = 300) -> str:
        """Read an allowed text file in chunks (offset in lines). Secrets are shown as ***."""
        return files.do_read_file(path, offset, max_lines)

    @mcp.tool(annotations=RO)
    @guard("search_files")
    def search_files(pattern: str, path: str, glob: str = "*", max_results: int = 100) -> str:
        """Search a regular expression in files under an allowed path (recursive, skips protected files)."""
        return files.do_search_files(pattern, path, glob, max_results)

    @mcp.tool(annotations=RO)
    @guard("tail_log")
    def tail_log(path: str, lines: int = 100) -> str:
        """Last N lines of a log file under the allowed log folders (default /var/log)."""
        return system.do_tail_log(path, lines)

    @mcp.tool(annotations=RO)
    @guard("service_status")
    def service_status(name: str) -> str:
        """Status of a systemd service (is-active + recent journal lines)."""
        return system.do_service_status(name)

    @mcp.tool(annotations=RO)
    @guard("asterisk_cli")
    def asterisk_cli(command: str, confirm: bool = False) -> str:
        """Asterisk CLI command: read-only ones (pjsip show..., core show channels...) run directly; reloads
        (only if the owner enabled the Asterisk profile) need confirm=true. Only on servers with Asterisk."""
        return system.do_asterisk_cli(command, confirm)

    @mcp.tool(annotations=RO)
    @guard("db_query")
    def db_query(sql: str, max_rows: int = 100) -> str:
        """One SELECT/SHOW/DESCRIBE/EXPLAIN statement on the configured MySQL/MariaDB (read-only user)."""
        return db.do_db_query(sql, max_rows)

    @mcp.tool(annotations=CMD)
    @guard("run_command")
    def run_command(command: str, cwd: str | None = None, timeout: int = 30, confirm: bool = False) -> str:
        """Run an allow-listed command (no shell: | ; > * are not interpreted). Path arguments must be in
        allowed folders. Commands that change things (cp, mv, git pull...) require confirm=true."""
        return commands.do_run_command(command, cwd, timeout, confirm)

    @mcp.tool(annotations=CMD)
    @guard("start_session")
    def start_session(command: str, cwd: str | None = None, confirm: bool = False) -> str:
        """Start an allow-listed command in the background; read its output with read_session."""
        return commands.do_start_session(command, cwd, confirm)

    @mcp.tool(annotations=RO)
    @guard("read_session")
    def read_session(session_id: str, wait: float = 2.0) -> str:
        """New output of a session since the last read."""
        return commands.do_read_session(session_id, wait)

    @mcp.tool(annotations=SESSION)
    @guard("stop_session")
    def stop_session(session_id: str) -> str:
        """Stop a session."""
        return commands.do_stop_session(session_id)

    @mcp.tool(annotations=RO)
    @guard("list_sessions")
    def list_sessions() -> str:
        """Open process sessions."""
        return commands.do_list_sessions()

    @mcp.tool(annotations=WRITE)
    @guard("write_file")
    def write_file(path: str, content: str, confirm: bool = False) -> str:
        """Write a file in allowed paths. Without confirm=true it only returns the diff. Backs up first."""
        return files.do_write_file(path, content, confirm)

    @mcp.tool(annotations=WRITE)
    @guard("edit_file")
    def edit_file(path: str, old: str, new: str, confirm: bool = False) -> str:
        """Replace one unique snippet of a file. Without confirm=true it only returns the diff. Backs up first."""
        return files.do_edit_file(path, old, new, confirm)

    @mcp.tool(annotations=SESSION)
    @guard("backup_create")
    def backup_create(path: str) -> str:
        """Timestamped copy of a file into the backups folder."""
        return files.do_backup_create(path)

    @mcp.tool(annotations=WRITE)
    @guard("service_restart")
    def service_restart(name: str, confirm: bool = False) -> str:
        """Restart a systemd service (requires confirm=true and the owner's sudo authorization)."""
        return system.do_service_restart(name, confirm)

    @mcp.tool(annotations=WRITE)
    @guard("service_reload")
    def service_reload(name: str, confirm: bool = False) -> str:
        """Send HUP to a service's main process (graceful reload, e.g. gunicorn/nginx; requires confirm=true)."""
        return system.do_service_reload(name, confirm)

    if cfg.full_access:
        # Profile "full" (owner opt-in with `sudo opsgate access`): a root shell, like SSH.
        @mcp.tool(annotations=CMD)
        @guard("run_shell")
        def run_shell(command: str, cwd: str | None = None, timeout: int = 60, background: bool = False) -> str:
            """FULL ACCESS: run a shell command (bash) as root on this server, like an SSH session. Pipes,
            redirects, mysql/curl/asterisk -rx and scripts work. background=true starts it detached; read its
            output with read_session. Every call is recorded in the audit log."""
            if background:
                return commands.do_start_shell(command, cwd)
            return commands.do_run_shell(command, cwd, timeout)

    @mcp.tool(annotations=RO)
    @guard("account_status", metered=False)
    def account_status() -> str:
        """OpsGate plan and this month's tool-call usage (does not count as a call)."""
        import meter
        m = meter.METER
        st = m.status()
        if not m.enabled:
            return f"OpsGate Agent {VERSION}: usage metering disabled on this server."
        if st["limit"] is not None:
            limit = f"{st['limit']:,}"
        else:
            limit = "unlimited" if st["plan"] else "unknown (not synced yet)"
        synced = "never" if not st["last_ok"] else time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(st["last_ok"]))
        return (f"OpsGate Agent {VERSION}\nPlan: {(st['plan'] or 'unknown').capitalize()}\n"
                f"Tool calls this month ({st['period']}, UTC): {m.total_used():,} / {limit}\n"
                f"Last sync with OpsGate Cloud: {synced}\n"
                f"Manage your plan: {st.get('upgrade_url') or (cfg.cloud_url + '/dashboard/billing')}")

    return mcp


if __name__ == "__main__":
    try:
        app = build()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    import meter
    meter.METER.start()  # first report right away: the dashboard shows the server online
    app.run(transport="streamable-http")
