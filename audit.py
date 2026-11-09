"""Local audit log (one JSON object per line) with rotation."""
from __future__ import annotations

import hashlib
import json
import logging
import logging.handlers
import time
from typing import Any

from config import cfg

_logger: logging.Logger | None = None


def _get() -> logging.Logger:
    global _logger
    if _logger is None:
        cfg.audit_file.parent.mkdir(parents=True, exist_ok=True)
        lg = logging.getLogger("opsgate.audit")
        lg.setLevel(logging.INFO)
        lg.propagate = False
        lg.handlers.clear()
        h = logging.handlers.RotatingFileHandler(
            cfg.audit_file, maxBytes=5_000_000, backupCount=10, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(message)s"))
        lg.addHandler(h)
        _logger = lg
    return _logger


def reset() -> None:
    """For tests: reopen the file with the current configuration."""
    global _logger
    if _logger:
        for h in list(_logger.handlers):
            h.close()
    _logger = None


def summarize(params: dict[str, Any]) -> dict[str, Any]:
    """Summarize params: long strings are stored as length + hash, never in full."""
    from security import redact  # late import: avoids an audit <-> security cycle

    out: dict[str, Any] = {}
    for k, v in params.items():
        if isinstance(v, str) and len(v) > 200:
            out[k] = {"len": len(v), "sha256": hashlib.sha256(v.encode()).hexdigest()[:16]}
        elif isinstance(v, str):
            out[k] = redact(v)
        else:
            out[k] = v
    return out


def log(tool: str, params: dict[str, Any], ok: bool, ms: int, note: str = "") -> None:
    rec = {"t": round(time.time(), 3), "tool": tool, "ok": ok, "ms": ms,
           "params": summarize(params)}
    if note:
        from security import redact
        rec["note"] = redact(note)[:300]
    _get().info(json.dumps(rec, ensure_ascii=False, default=str))
