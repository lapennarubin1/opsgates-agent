"""Usage metering against OpsGate Cloud.

Privacy model: the agent only ever sends a NUMBER (how many tool calls happened since the last
report), a random agent id, the agent version and this server's public connector URL (so the
customer's dashboard can show it). Never tool names, arguments, paths, output or credentials.

- Counts are kept locally (state_dir/meter.json) and reported in batches every 30 s, or sooner
  when 20 calls are pending. Every batch has an id, so a retried batch is never counted twice.
- When idle, the agent sends an empty report every 5 minutes (heartbeat) so the dashboard can
  show the server as online and the plan stays fresh.
- The cloud answers with the plan, the monthly limit and the current usage. When the limit is
  reached, tool calls are refused with a clear upgrade message until the plan changes or the
  month rolls over (UTC calendar month).
- If the cloud is unreachable, the agent keeps working and counting locally for
  OPSGATE_OFFLINE_GRACE_HOURS (72 h by default), then refuses calls until it can report again.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

from config import VERSION, cfg

FLUSH_EVERY = 30          # seconds between reports while there is something to report
FLUSH_AT_PENDING = 20     # report sooner when this many calls are pending
HEARTBEAT = 300           # empty report when idle, so the dashboard shows the server online
SYNC_CHECK_MIN_INTERVAL = 10
MAX_BACKOFF = 300


class QuotaError(Exception):
    """Raised when a tool call must be refused (limit reached, invalid key, offline too long)."""


def current_period(now: float | None = None) -> str:
    return datetime.fromtimestamp(now or time.time(), tz=timezone.utc).strftime("%Y-%m")


def _fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16] if key else ""


class Meter:
    def __init__(self, state_file: Path, license_key: str, cloud_url: str, enabled: bool,
                 grace_hours: int, transport: httpx.BaseTransport | None = None, public_url: str = ""):
        self.state_file = state_file
        self.key = license_key
        self.url = cloud_url.rstrip("/")
        self.enabled = enabled
        self.grace = grace_hours * 3600
        self.public_url = public_url
        self._transport = transport
        self._lock = threading.RLock()
        self._flush_lock = threading.Lock()
        self._wake = threading.Event()
        self._last_sync_check = 0.0
        self._last_attempt = 0.0
        self._failures = 0
        self._thread: threading.Thread | None = None
        self.st = self._load()

    # ------------------------------------------------------------------ state
    def _load(self) -> dict:
        st = {"agent_id": "ag_" + secrets.token_hex(8), "pending": 0, "inflight": None,
              "used": 0, "limit": None, "plan": None, "allowed": True, "period": current_period(),
              "last_ok": None, "first_seen": time.time(), "invalid_key": False, "upgrade_url": "",
              "message": "", "key_fp": _fingerprint(self.key)}
        try:
            saved = json.loads(self.state_file.read_text())
            if isinstance(saved, dict):
                st.update(saved)
        except (OSError, ValueError):
            pass
        if st.get("key_fp") != _fingerprint(self.key):
            # A different license key was configured: forget everything learned about the old one,
            # but keep pending counts (they were real calls) and the agent id.
            st.update(key_fp=_fingerprint(self.key), invalid_key=False, limit=None, plan=None,
                      allowed=True, used=0, last_ok=None, first_seen=time.time(), message="", upgrade_url="")
        return st

    def _save(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.st))
            os.replace(tmp, self.state_file)
        except OSError:
            pass  # metering must never take the agent down because of a disk issue

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.key and self.url)

    # ------------------------------------------------------------------ public API
    def start(self) -> None:
        """Start the background reporter and send a first report right away (server startup)."""
        if self.configured:
            self._ensure_thread()
            self._wake.set()

    def before_call(self) -> None:
        """Raise QuotaError if this call must be refused. Called before every tool call."""
        if not self.enabled:
            return
        if not self.key or not self.url:
            raise QuotaError("This OpsGate agent has no license key. Create a free key in your OpsGate "
                             "dashboard and run: sudo opsgate license <key>")
        self._ensure_thread()
        with self._lock:
            if self.st["period"] != current_period():  # new month: local view resets
                self.st.update(period=current_period(), used=0, allowed=True)
                self._save()
        if self._must_refuse():
            self._sync_check()  # the plan may have just been upgraded: ask the cloud before refusing
            reason = self._must_refuse()
            if reason:
                raise QuotaError(reason)

    def count(self) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.st["pending"] += 1
            pending = self.st["pending"]
            self._save()
        if pending >= FLUSH_AT_PENDING:
            self._wake.set()

    def status(self) -> dict:
        with self._lock:
            return dict(self.st)

    def total_used(self) -> int:
        with self._lock:
            st = self.st
            return st["used"] + st["pending"] + (st["inflight"] or {}).get("delta", 0)

    # ------------------------------------------------------------------ decisions
    def _must_refuse(self) -> str:
        with self._lock:
            st = self.st
            upgrade = st.get("upgrade_url") or (self.url + "/dashboard/billing")
            if st["invalid_key"]:
                return ("The OpsGate license key was rejected (revoked or invalid). Create a new key in "
                        f"{self.url}/dashboard and run: sudo opsgate license <key>")
            since = st["last_ok"] or st["first_seen"]
            if time.time() - since > self.grace:
                return (f"OpsGate could not reach its license server for more than "
                        f"{self.grace // 3600} hours, so tool calls are paused. Check this server's "
                        f"internet access to {self.url}.")
            limit = st["limit"]
            if limit is not None and self.total_used() >= limit:
                plan = (st["plan"] or "current").capitalize()
                return (f"Monthly tool-call limit reached ({limit:,} on the {plan} plan). "
                        f"Upgrade at {upgrade} — usage resets on the 1st of each month (UTC).")
            if not st["allowed"]:
                return f"Tool calls are paused for this account. See {upgrade}"  # fixed text: never the server's wording
            return ""

    def _sync_check(self) -> None:
        now = time.monotonic()
        if now - self._last_sync_check < SYNC_CHECK_MIN_INTERVAL:
            return
        self._last_sync_check = now
        self.flush()

    # ------------------------------------------------------------------ reporting
    def flush(self) -> bool:
        """Report pending calls (or retry the in-flight batch). Returns True on success."""
        if not self.configured:
            return False
        with self._flush_lock:  # one report at a time; the in-flight batch is shared by retries
            return self._flush_locked()

    def _flush_locked(self) -> bool:
        with self._lock:
            if self.st["inflight"] is None:
                self.st["inflight"] = {"id": "b_" + secrets.token_hex(12), "delta": self.st["pending"]}
                self.st["pending"] = 0
                self._save()
            batch = dict(self.st["inflight"])
            agent_id = self.st["agent_id"]
        self._last_attempt = time.monotonic()
        body = {"delta": batch["delta"], "batch_id": batch["id"], "agent_id": agent_id, "version": VERSION}
        if self.public_url:
            body["url"] = self.public_url
        try:
            with httpx.Client(transport=self._transport, timeout=10) as c:
                r = c.post(f"{self.url}/api/v1/usage", headers={"Authorization": f"Bearer {self.key}"},
                           json=body)
        except httpx.HTTPError:
            self._failures += 1
            return False
        with self._lock:
            if r.status_code in (401, 403):
                self.st["invalid_key"] = True
                self.st["inflight"] = None  # nothing to bill against a revoked key
                self._save()
                self._failures = 0
                return False
            if r.status_code != 200:
                self._failures += 1
                return False
            try:
                d = r.json()
            except ValueError:
                self._failures += 1
                return False
            limit = d.get("limit")
            self.st.update(inflight=None, used=int(d.get("used", 0)),
                           limit=int(limit) if isinstance(limit, (int, float)) else None,
                           plan=d.get("plan"), allowed=bool(d.get("allowed", True)),
                           period=d.get("period") or current_period(), last_ok=time.time(),
                           invalid_key=False, upgrade_url=self._safe_upgrade_url(d.get("upgrade_url", "")),
                           latest_version=self._safe_version(d.get("latest_version")),
                           message="")
            self._save()
            self._failures = 0
            return True

    @staticmethod
    def _safe_version(value) -> str:
        v = str(value or "")[:20]
        return v if v and all(c.isdigit() or c == "." for c in v) else ""

    def _safe_upgrade_url(self, value) -> str:
        """Only links on the configured cloud address are ever shown to the AI."""
        v = str(value)[:300]
        return v if v.startswith(self.url.rstrip("/") + "/") else ""

    def _due(self) -> bool:
        with self._lock:
            busy = self.st["pending"] > 0 or self.st["inflight"] is not None
            last_ok = self.st["last_ok"] or 0
        backoff = min(FLUSH_EVERY * (2 ** max(self._failures - 1, 0)), MAX_BACKOFF) if self._failures else 0
        if time.monotonic() - self._last_attempt < backoff:
            return False
        return busy or time.time() - last_ok >= HEARTBEAT

    def _ensure_thread(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._loop, name="opsgate-meter", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while True:
            self._wake.wait(FLUSH_EVERY)
            woken = self._wake.is_set()
            self._wake.clear()
            try:
                if woken or self._due():
                    self.flush()
            except Exception:  # noqa: BLE001 - the reporter thread must never die
                self._failures += 1


def _public_mcp_url() -> str:
    u = cfg.public_url.rstrip("/")
    return "" if (not u or "example.invalid" in u) else u + "/mcp"


METER = Meter(cfg.state_dir / "meter.json", cfg.license_key, cfg.cloud_url, cfg.metering,
              cfg.offline_grace_hours, public_url=_public_mcp_url())
