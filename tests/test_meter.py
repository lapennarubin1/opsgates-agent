"""Tests for meter.py's usage metering against OpsGate Cloud.

Uses httpx.MockTransport to stand in for the cloud's /api/v1/usage endpoint,
so no real network calls happen.
"""
from __future__ import annotations

import json

import httpx
import pytest

from meter import Meter, QuotaError, current_period


class FakeCloud:
    """A tiny fake usage endpoint. responses is a list of dicts popped in order;
    each call records the request for inspection."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.seen_batch_ids = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return httpx.Response(401, json={"error": "missing token"})
        key = auth.removeprefix("Bearer ")
        if key != "og_validkey_1234567890":
            return httpx.Response(401, json={"error": "invalid key"})
        if not self.responses:
            return httpx.Response(500, json={"error": "no more canned responses"})
        status, payload = self.responses.pop(0)
        return httpx.Response(status, json=payload)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def make_meter(tmp_path, cloud: FakeCloud, *, enabled=True, grace_hours=72, key="og_validkey_1234567890"):
    return Meter(tmp_path / "meter.json", key, "https://cloud.example.invalid", enabled,
                 grace_hours, transport=cloud.transport())


def test_disabled_meter_never_blocks(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud, enabled=False)
    m.before_call()  # must not raise, must not touch the network
    m.count()
    assert cloud.requests == []


def test_no_license_key_refuses(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud, key="")
    with pytest.raises(QuotaError, match="license key"):
        m.before_call()


def test_successful_flush_updates_status(tmp_path):
    cloud = FakeCloud([(200, {"used": 3, "limit": 5000, "plan": "free", "allowed": True,
                               "period": current_period()})])
    m = make_meter(tmp_path, cloud)
    m.before_call()
    m.count()
    m.count()
    m.count()
    assert m.flush() is True
    st = m.status()
    assert st["used"] == 3
    assert st["limit"] == 5000
    assert st["plan"] == "free"
    assert st["pending"] == 0
    assert st["inflight"] is None
    assert len(cloud.requests) == 1
    assert cloud.requests[0]["delta"] == 3


def test_before_call_raises_when_limit_reached(tmp_path):
    cloud = FakeCloud([(200, {"used": 5000, "limit": 5000, "plan": "free", "allowed": True,
                               "period": current_period()})])
    m = make_meter(tmp_path, cloud)
    m.before_call()
    m.flush()
    with pytest.raises(QuotaError, match="limit reached"):
        m.before_call()


def test_unlimited_plan_never_refused(tmp_path):
    cloud = FakeCloud([(200, {"used": 999999, "limit": None, "plan": "unlimited", "allowed": True,
                               "period": current_period()})])
    m = make_meter(tmp_path, cloud)
    m.before_call()
    m.flush()
    m.before_call()  # must not raise despite a huge used count


def test_invalid_key_refuses(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud, key="og_wrongkey_0000000000")
    m.before_call()
    m.flush()
    with pytest.raises(QuotaError, match="rejected"):
        m.before_call()


def test_offline_past_grace_period_refuses(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud, grace_hours=0)
    with m._lock:
        m.st["first_seen"] -= 1  # make sure "since" is already in the past
    with pytest.raises(QuotaError, match="could not reach"):
        m.before_call()


def test_retry_uses_same_batch_id(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud)
    m.count()
    m.count()
    assert m.flush() is False  # first attempt: no canned response, fails
    batch_id_1 = m.status()["inflight"]["id"]
    cloud.responses.append((200, {"used": 2, "limit": 5000, "plan": "free", "allowed": True,
                                   "period": current_period()}))
    assert m.flush() is True  # retry must reuse the same batch, not create a new one
    batch_id_2 = cloud.requests[-1]["batch_id"]
    assert batch_id_2 == batch_id_1


def test_state_persists_and_reloads(tmp_path):
    cloud = FakeCloud([(200, {"used": 7, "limit": 15000, "plan": "pro", "allowed": True,
                               "period": current_period()})])
    m1 = make_meter(tmp_path, cloud)
    m1.before_call()
    m1.flush()
    m2 = make_meter(tmp_path, cloud)  # fresh instance, same state file
    st = m2.status()
    assert st["used"] == 7
    assert st["plan"] == "pro"
    assert st["agent_id"] == m1.status()["agent_id"]


def test_flush_triggers_automatically_near_threshold(tmp_path):
    from meter import FLUSH_AT_PENDING
    cloud = FakeCloud([(200, {"used": FLUSH_AT_PENDING, "limit": 5000, "plan": "free",
                               "allowed": True, "period": current_period()})])
    m = make_meter(tmp_path, cloud)
    for _ in range(FLUSH_AT_PENDING):
        m.count()
    assert m._wake.is_set()


def test_cloud_wording_is_never_shown_when_not_allowed(tmp_path):
    cloud = FakeCloud([(200, {"used": 10, "limit": 5000, "plan": "free", "allowed": False,
                               "period": current_period(), "message": "Payment failed; update your card.",
                               "upgrade_url": "https://cloud.example.invalid/billing"})])
    m = make_meter(tmp_path, cloud)
    m.before_call()
    m.flush()
    with pytest.raises(QuotaError, match="Tool calls are paused") as e:
        m.before_call()
    assert "Payment failed" not in str(e.value)  # a hacked cloud cannot write text for the AI to read


def test_report_carries_only_counts_and_ids(tmp_path):
    cloud = FakeCloud([(200, {"used": 1, "limit": 5000, "plan": "free", "allowed": True,
                               "period": current_period()})])
    m = Meter(tmp_path / "meter.json", "og_validkey_1234567890", "https://cloud.example.invalid", True, 72,
              transport=cloud.transport(), public_url="https://srv.example.com/mcp")
    m.count()
    assert m.flush() is True
    sent = cloud.requests[0]
    assert set(sent) == {"delta", "batch_id", "agent_id", "version", "url"}
    assert sent["url"] == "https://srv.example.com/mcp"
    assert sent["agent_id"].startswith("ag_")


def test_new_license_key_clears_rejected_state(tmp_path):
    cloud = FakeCloud([])
    m1 = make_meter(tmp_path, cloud, key="og_wrongkey_0000000000")
    m1.count()
    m1.flush()
    assert m1.status()["invalid_key"] is True
    m2 = make_meter(tmp_path, cloud)  # owner configured a new, valid key
    st = m2.status()
    assert st["invalid_key"] is False
    assert st["agent_id"] == m1.status()["agent_id"]
    m2.before_call()  # no longer refused


def test_heartbeat_due_when_idle_and_stale(tmp_path):
    import meter
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud)
    assert m._due() is True  # never reported: due right away
    with m._lock:
        m.st["last_ok"] = __import__("time").time()
    assert m._due() is False  # idle and fresh: nothing to send
    m.count()
    assert m._due() is True  # pending calls: due
    assert meter.HEARTBEAT >= 60


def test_failures_back_off(tmp_path):
    cloud = FakeCloud([])
    m = make_meter(tmp_path, cloud)
    m.count()
    assert m.flush() is False and m.flush() is False
    assert m._failures == 2
    assert m._due() is False  # just failed: waits before retrying


def test_garbage_state_file_is_ignored(tmp_path):
    (tmp_path / "meter.json").write_text("[not a dict]")
    m = make_meter(tmp_path, FakeCloud([]))
    assert m.status()["pending"] == 0


def test_cloud_cannot_put_its_own_words_or_foreign_links_in_front_of_the_ai():
    import meter
    m = meter.Meter.__new__(meter.Meter)
    m.url = "https://cloud.example"
    assert m._safe_upgrade_url("https://evil.test/pay") == ""
    assert m._safe_upgrade_url("https://cloud.example/dashboard/billing") == "https://cloud.example/dashboard/billing"
