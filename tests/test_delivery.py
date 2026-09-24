import hashlib
import hmac
import json

import pytest

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
