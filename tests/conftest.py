import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("MCP_TOKEN_SHA256", "0" * 64)
os.environ.setdefault("MCP_AUDIT_FILE", "/tmp/opsgate-test/audit.jsonl")
os.environ.setdefault("OPSGATE_METERING", "off")  # metering has its own tests (test_meter.py)

import audit  # noqa: E402
import security  # noqa: E402
from config import cfg  # noqa: E402


@pytest.fixture
def env(tmp_path):
    """Isolated environment: allowed root, a folder outside it, backups and audit in tmp."""
    root = tmp_path / "staging"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secreto.txt").write_text("fuera")
    logs = tmp_path / "logs"
    logs.mkdir()
    saved = {k: getattr(cfg, k) for k in
             ("read_roots", "write_roots", "log_roots", "backup_dir", "audit_file", "rate_per_minute")}
    cfg.read_roots = [root.resolve()]
    cfg.write_roots = [root.resolve()]
    cfg.log_roots = [logs.resolve()]
    cfg.backup_dir = tmp_path / "backups"
    cfg.audit_file = tmp_path / "audit" / "audit.jsonl"
    cfg.rate_per_minute = 1000
    audit.reset()
    security.reset_rate_limit()
    yield {"root": root.resolve(), "outside": outside.resolve(), "logs": logs.resolve(), "tmp": tmp_path}
    for k, v in saved.items():
        setattr(cfg, k, v)
    audit.reset()
