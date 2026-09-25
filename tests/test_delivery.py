import asyncio
import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest

import ntfy_hermes_bridge.daemon as daemon_module
from ntfy_hermes_bridge.daemon import App
from ntfy_hermes_bridge.models import Route

from .conftest import ntfy_line

pytestmark = pytest.mark.anyio


async def notify(app: App, mid: str = "M1") -> None:
    app.ingest_line("alerts", ntfy_line(mid, "zpool tank is DEGRADED", title="TrueNAS"))
    for row in app.store.claim_received(10):
        await app.pipeline.process(row)


def outbox(app: App) -> list:
    return app.store.conn.execute("SELECT * FROM outbox ORDER BY id").fetchall()


async def test_hermes_requests_are_signed_v2_and_idempotent(make_config, services):
    app = App(make_config(bridge__mode="guarded"), transport=services.transport())
    await notify(app)
    await app.deliver(outbox(app)[0])

    [request] = services.hermes_requests
    assert request.url.path == "/webhooks/notification-compose"
    timestamp = request.headers["X-Webhook-Timestamp"]
    expected = hmac.new(b"test-hermes-secret", f"{timestamp}.".encode() + request.content, hashlib.sha256).hexdigest()
    assert request.headers["X-Webhook-Signature-V2"] == expected
    assert request.headers["X-Request-ID"] == "ntfy:alerts:M1"
    payload = json.loads(request.content)
    assert payload["event_type"] == "notification.compose"
    assert payload["deterministic_rule"] == "signature:storage_degraded"
    assert app.store.get_event("ntfy:alerts:M1")["status"] == "delivered"
    await app.close()


async def test_source_profiles_route_reviews_and_critical_alerts_to_distinct_agents(make_config, services):
    app = App(
        make_config(
            bridge__mode="guarded",
            ntfy__topics=[{"name": name} for name in ("arr", "cross-seed", "change")],
            hermes__source_profiles={"arr": "torry", "cross-seed": "torry"},
        ),
        transport=services.transport(),
    )
    for topic, mid in (("arr", "A1"), ("cross-seed", "C1"), ("change", "I1")):
        app.ingest_line(topic, ntfy_line(mid, "routine change", topic=topic))
    app.ingest_line("arr", ntfy_line("A2", "zpool tank DEGRADED", topic="arr"))
    for row in app.store.claim_received(4):
        await app.pipeline.process(row)
    for row in outbox(app):
        await app.deliver(row)

    assert {
        (json.loads(req.content)["source"], json.loads(req.content)["event_type"], req.url.path)
        for req in services.hermes_requests
    } == {
        ("arr", "notification.review", "/p/torry/webhooks/notification-review-torry"),
        ("arr", "notification.compose", "/p/torry/webhooks/notification-compose-torry"),
        ("cross-seed", "notification.review", "/p/torry/webhooks/notification-review-torry"),
        ("change", "notification.review", "/webhooks/notification-review"),
    }
    await app.close()


async def test_transient_failures_retry_then_deliver(make_config, services):
    services.hermes_status = [503]
    app = App(make_config(bridge__mode="guarded"), transport=services.transport())
    await notify(app)
    await app.deliver(outbox(app)[0])
    row = outbox(app)[0]
    assert row["status"] == "pending" and row["attempts"] == 1 and "503" in row["last_error"]
    assert row["next_attempt_at"] > row["created_at"]

    await app.deliver(row)
    assert outbox(app)[0]["status"] == "delivered"
    assert services.hermes_requests[0].headers["X-Request-ID"] == services.hermes_requests[1].headers["X-Request-ID"]
    await app.close()


async def test_permanent_failure_dead_letters_and_falls_back_to_clean_ntfy(make_config, services):
    services.hermes_status = [404]
    config = make_config(bridge__mode="full", fallback__ntfy_topic="alerts-clean")
    app = App(config, transport=services.transport())
    await notify(app)
    await app.deliver(outbox(app)[0])

    compose, fallback = outbox(app)
    assert compose["status"] == "dead"
    assert app.store.get_event("ntfy:alerts:M1")["status"] == "dead_letter"
    assert fallback["kind"] == "fallback_ntfy"
    await app.deliver(fallback)
    [published] = services.ntfy_publishes
    assert published["topic"] == "alerts-clean"
    assert "hermes-bridge" in published["tags"]  # echo tag prevents a loop if the topic is ever subscribed
    assert "Ref: M1" in published["message"]

    assert app.store.requeue_dead(None) == 1
    assert app.store.get_event("ntfy:alerts:M1")["status"] == "queued"
    await app.close()


async def test_retries_exhaust_into_dead_letter(make_config, services):
    services.hermes_status = [503, 503]
    app = App(make_config(bridge__mode="guarded", outbox__max_attempts=2), transport=services.transport())
    await notify(app)
    await app.deliver(outbox(app)[0])
    await app.deliver(outbox(app)[0])
    assert outbox(app)[0]["status"] == "dead"
    await app.close()


async def test_health_alert_is_routed_as_always_notify_once_per_outage(make_config, services):
    app = App(make_config(bridge__mode="full"), transport=services.transport())
    app.check_alert("delivery_outage", True, "Hermes delivery degraded")
    app.check_alert("delivery_outage", True, "Hermes delivery degraded")
    [row] = app.store.claim_received(10)
    decision = await app.pipeline.process(row)
    assert decision.rule == "bridge_health" and decision.effective == Route.NOTIFY_NOW
    assert services.jev_requests == []
    app.check_alert("delivery_outage", False, "")
    app.check_alert("delivery_outage", True, "again")
    assert len(app.store.claim_received(10)) == 1
    await app.close()


async def test_outbox_loop_recovers_and_isolates_sibling_deliveries(make_config, services, monkeypatch):
    app = App(make_config(), transport=services.transport())
    due_calls = 0
    attempted = []
    sleeps = []

    def due_outbox(*_args):
        nonlocal due_calls
        due_calls += 1
        if due_calls == 1:
            raise RuntimeError("temporary database failure")
        if due_calls == 2:
            return [{"id": 1}, {"id": 2}]
        raise asyncio.CancelledError

    async def deliver(row):
        attempted.append(row["id"])
        if row["id"] == 1:
            raise RuntimeError("temporary delivery failure")

    async def sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(app.store, "due_outbox", due_outbox)
    monkeypatch.setattr(app, "deliver", deliver)
    monkeypatch.setattr(daemon_module.asyncio, "sleep", sleep)

    with pytest.raises(asyncio.CancelledError):
        await app.outbox_loop()

    assert attempted == [1, 2]
    assert sleeps == [daemon_module.LOOP_RETRY_SECONDS, daemon_module.LOOP_RETRY_SECONDS]
    await app.close()


async def test_digest_loop_recovers_without_swallowing_cancellation(make_config, services, monkeypatch):
    app = App(make_config(), transport=services.transport())
    calls = 0

    def run_digest(*_args):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary database failure")
        if calls == 2:
            return 2
        raise asyncio.CancelledError

    async def sleep(_delay):
        pass

    monkeypatch.setattr(daemon_module, "run_due_digest", run_digest)
    monkeypatch.setattr(daemon_module.asyncio, "sleep", sleep)

    with pytest.raises(asyncio.CancelledError):
        await app.digest_loop()

    assert calls == 3
    assert app.outbox_wake.is_set()
    assert app.metrics.value("digests_total") == 2
    await app.close()


async def test_maintenance_loop_recovers_without_swallowing_cancellation(make_config, services, monkeypatch):
    app = App(make_config(), transport=services.transport())
    refresh_calls = 0
    prune_calls = []

    async def refresh_guardrail():
        nonlocal refresh_calls
        refresh_calls += 1
        if refresh_calls == 1:
            raise RuntimeError("temporary guardrail failure")
        if refresh_calls == 3:
            raise asyncio.CancelledError

    async def sleep(_delay):
        pass

    monkeypatch.setattr(app, "refresh_guardrail", refresh_guardrail)
    monkeypatch.setattr(app.store, "prune", lambda days: prune_calls.append(days) or 0)
    monkeypatch.setattr(daemon_module.asyncio, "sleep", sleep)
    monkeypatch.setattr(daemon_module, "PRUNE_INTERVAL_SECONDS", -1)

    with pytest.raises(asyncio.CancelledError):
        await app.maintenance_loop()

    assert refresh_calls == 3
    assert prune_calls == [app.config.retention.days]
    await app.close()


async def test_quarantine_growth_alerts_only_for_new_growth(make_config, services):
    config = make_config()
    app = App(config, transport=services.transport())
    app.ingest_line("alerts", "historical invalid input")
    await app.close()

    app = App(config, transport=services.transport())
    app._check_health_alerts(app.health())
    assert (
        app.store.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_id LIKE 'bridge:quarantine_growth:%'"
        ).fetchone()["n"]
        == 0
    )

    app.ingest_line("alerts", "new invalid input")
    app._check_health_alerts(app.health())
    app._check_health_alerts(app.health())
    assert (
        app.store.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_id LIKE 'bridge:quarantine_growth:%'"
        ).fetchone()["n"]
        == 1
    )

    app.ingest_line("alerts", "another invalid input")
    app._check_health_alerts(app.health())
    assert (
        app.store.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_id LIKE 'bridge:quarantine_growth:%'"
        ).fetchone()["n"]
        == 2
    )
    await app.close()


async def test_stalled_nonterminal_event_degrades_health_and_alerts(make_config, services):
    app = App(make_config(), transport=services.transport())
    app.ingest_line("alerts", ntfy_line("M-stalled"))
    assert app.health()["status"] == "ok"

    old = (datetime.now(UTC) - timedelta(days=2)).isoformat(timespec="microseconds")
    app.store.conn.execute(
        "UPDATE events SET received_at = ?, occurred_at = ? WHERE event_id = ?",
        (old, old, "ntfy:alerts:M-stalled"),
    )
    snapshot = app.health()
    assert snapshot["events_stalled"]
    assert snapshot["status"] == "degraded"

    app._check_health_alerts(snapshot)
    app._check_health_alerts(app.health())
    rows = app.store.conn.execute(
        "SELECT raw_json FROM events WHERE event_id LIKE 'bridge:events_stalled:%'"
    ).fetchall()
    assert len(rows) == 1
    await app.close()


async def test_alert_retries_after_event_persistence_failure(make_config, services, monkeypatch):
    app = App(make_config(), transport=services.transport())
    original_ingest = app.store.ingest
    attempts = 0

    def flaky_ingest(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("database temporarily unavailable")
        return original_ingest(**kwargs)

    monkeypatch.setattr(app.store, "ingest", flaky_ingest)
    with pytest.raises(OSError):
        app.check_alert("replay_truncated", True, "replay lost", key="replay_truncated:alerts")
    app.check_alert("replay_truncated", True, "replay lost", key="replay_truncated:alerts")
    assert attempts == 2
    assert (
        app.store.conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_id LIKE 'bridge:replay_truncated:%'"
        ).fetchone()[0]
        == 1
    )
    assert app.metrics.value("health_alerts_total", kind="replay_truncated") == 1
    await app.close()
