# OpsGates Agent

**A secure, self-hosted [MCP](https://modelcontextprotocol.io) server that lets Claude, ChatGPT, Claude Code, Cursor, VS Code and Codex operate your Linux server — inside limits you set.**

Your passwords, tokens, files and command output never leave your server. The agent runs as an
unprivileged user in a hardened systemd sandbox, previews every change before making it, and keeps
a local audit log of every call.

Website: <https://opsgates.com> · Docs: <https://opsgates.com/docs>

## Why

Giving an AI assistant a shell on a production server is risky. OpsGates is built around the
opposite default: the agent can read what an ordinary user can read, and *nothing else* unless you
explicitly allow it.

- **Read-only by default.** Writing files and restarting services are opt-in, per folder and per service.
- **Preview, then confirm.** Every state-changing tool returns a preview first and only runs with `confirm=true`.
- **No shell by default.** Commands run from an allow-list, without a shell; options that execute programs or write files are refused.
- **Secrets stay masked.** Anything that looks like a secret is shown as `***`; secret files cannot be read.
- **Tamper-resistant.** The agent cannot modify its own code, configuration, state or logs.
- **Auditable.** Every call is written to `/var/log/opsgate/audit.jsonl`.
- **OAuth 2.1 built in** (PKCE, dynamic client registration, hashed tokens), plus optional TOTP two-factor sign-in.

## Tools

| Group | Tools |
|---|---|
| Files | `list_dir`, `read_file`, `search_files`, `write_file`, `edit_file`, `backup_create` |
| Commands | `run_command`, `run_shell` (opt-in), `start_session`, `read_session`, `stop_session`, `list_sessions` |
| Services & logs | `service_status`, `service_restart`, `service_reload`, `tail_log` |
| Database | `db_query` (read-only) |
| Telephony | `asterisk_cli` |
| Account | `account_status` |

## Quick start

1. Create a free account at <https://opsgates.com>, add a server, and run the command it shows:

   ```bash
   curl -fsSL https://<your-opsgates-site>/install.sh | sudo bash -s -- --key og_...
   ```

2. Add the connector URL printed by the installer to your assistant
   (for example Claude → Settings → Connectors → Add custom connector) and sign in with the
   password the installer printed.
3. Manage it any time with `sudo opsgate help`.

Always read an installer before piping it to a shell. `deploy/install.sh` is in this repository.

## Permissions

```bash
sudo opsgate allow-write /srv/app/config     # let the agent write in this folder
sudo opsgate allow-restart nginx             # let it restart this service (exact sudo rule)
sudo opsgate help                            # all management commands
```

## Usage metering

`meter.py` sends **only call counts** to OpsGates Cloud, to apply your plan's monthly allowance.
No commands, paths, file contents or output are ever sent. The source is in this repository.

## Repository layout

| Path | Purpose |
|---|---|
| `server.py` | MCP server (FastMCP, Streamable HTTP) |
| `oauth.py` | Built-in OAuth 2.1 authorization server |
| `auth.py` | Static bearer tokens (SHA-256 only) |
| `security.py` | Path confinement, secret redaction, rate limit, the decorator every tool goes through |
| `meter.py` | Usage metering (call counts only) |
| `audit.py` | Local JSONL audit log |
| `tools/` | Files, commands, services/logs/Asterisk, read-only database |
| `bin/opsgate` | Management command (permissions, passwords, tokens, updates) |
| `deploy/` | Installer, hardened systemd unit, uninstaller |
| `scripts/` | Helpers used by the installer and the `opsgate` command, and `doctor.py` |
| `tests/` | Test suite |

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```

Tested with Python 3.12 and 3.13. Dependencies are pinned.

## Security

Found a vulnerability? Please read [SECURITY.md](SECURITY.md) and report it privately.

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GNU AGPL-3.0](LICENSE). You can use, study, modify and self-host the agent freely. If you offer a
modified version to others as a service, you must publish your changes under the same license.

Need to embed OpsGates in a closed-source product or resell it? Commercial licenses and a partner /
affiliate programme are available: see <https://opsgates.com> for contact details.
