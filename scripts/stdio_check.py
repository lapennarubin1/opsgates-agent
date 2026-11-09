"""Run the agent over stdio so MCP directories (Glama, MCP Inspector) can list its tools.

This is NOT how OpsGates runs in production (there it is a hardened systemd service behind OAuth /
bearer tokens over HTTPS). It starts the same server with throw-away state in /tmp, read-only access
and no network metering, and only talks to the process that launched it over stdin/stdout.
"""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

tmp = Path(tempfile.mkdtemp(prefix="opsgate-check-"))
os.environ.setdefault("MCP_TOKEN_SHA256", "0" * 64)       # placeholder, unused over stdio
os.environ.setdefault("MCP_AUDIT_FILE", str(tmp / "audit.jsonl"))
os.environ.setdefault("MCP_STATE_DIR", str(tmp / "state"))
os.environ.setdefault("MCP_BACKUP_DIR", str(tmp / "backups"))
os.environ.setdefault("MCP_ACCESS", "readonly")

import server  # noqa: E402

if __name__ == "__main__":
    server.build().run(transport="stdio")
