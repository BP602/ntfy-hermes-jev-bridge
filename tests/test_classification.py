import json

import httpx
import pytest

from ntfy_hermes_bridge.config import Thresholds
from ntfy_hermes_bridge.daemon import App
from ntfy_hermes_bridge.jev import JevAnswers
from ntfy_hermes_bridge.models import Route
from ntfy_hermes_bridge.policy import gate, route_from_answers
from ntfy_hermes_bridge.questions import NOUL_QUESTIONS

from .conftest import jev_answers, ntfy_line

pytestmark = pytest.mark.anyio


async def run(app: App, *lines: str):
    for line in lines:
        app.ingest_line("alerts", line)
    return [await app.pipeline.process(row) for row in app.store.claim_received(100)]


def outbox(app: App) -> list:
    return app.store.conn.execute("SELECT * FROM outbox ORDER BY id").fetchall()


async def test_valid_jev_response_is_validated_stored_and_routed_locally(make_config, services):
    services.jev_default = jev_answers(category="availability", confidence=0.66, harm=0.3, digest=0.7)
    app = App(make_config(), transport=services.transport())
    [decision] = await run(app, ntfy_line("M1", "nextcloud cron job took longer than usual", title="Nextcloud"))

    request = services.jev_requests[0]
    assert request["model"] == "jev-1.13.0"
    assert set(request["questions"]) == {"category", *NOUL_QUESTIONS}
    assert set(request["state"]) == {
        "source",
        "event_kind",
        "entity",
        "priority_label",
        "tags",
        "title",
        "message_excerpt",
        "repeat_bucket",
        "recency_bucket",
        "user_policy",
    }

    row = app.store.latest_decision("ntfy:alerts:M1")
    answers = json.loads(row["jev_answers_json"])
    assert answers["category"]["choice"] == "availability"
    assert answers["category"]["confidence"] == 0.66
    assert answers["digest_value"] == 0.7
    assert row["jev_model"] == "jev-1.13.0"
    assert row["question_set_version"] == "ops-notification-v1"
    assert row["policy_version"] == "test-1"
    assert row["input_tokens"] == 400
    assert row["proposed_route"] == "DIGEST"  # digest_value 0.7 >= 0.65 in code, not a Jev label
    assert decision.effective == "SHADOW"
    await app.close()


@pytest.mark.parametrize(
    "failure",
    [
        [httpx.Response(529), httpx.Response(529), httpx.Response(529)],
        [httpx.Response(429), httpx.Response(429), httpx.Response(429)],
        [httpx.Response(200, json={"model": "jev-1.13.0", "answers": {}})],
        [httpx.Response(401, json={"error": "bad key"})],
    ],
    ids=["overloaded", "rate-limited", "invalid-schema", "auth"],
)
async def test_classifier_failure_never_drops(make_config, services, failure):
    services.jev = list(failure)
    services.jev_default = None
    app = App(make_config(bridge__mode="full"), transport=services.transport())
    [decision] = await run(app, ntfy_line("M1", "weekly report generated", priority=2))
    assert decision.jev is None and decision.jev_error
    assert decision.proposed is Route.DIGEST
    assert app.store.get_event("ntfy:alerts:M1")["status"] == "queued_digest"
    assert len(services.jev_requests) == len(failure)  # retryable errors use the budget; others stop at once
    await app.close()


async def test_classifier_outage_still_notifies_deterministic_matches(make_config, services):
    services.jev_default = None
    services.jev = [httpx.Response(529)] * 9
    app = App(make_config(bridge__mode="full"), transport=services.transport())
    critical, high = await run(
        app,
        ntfy_line("M1", "Scrub found checksum errors: pool tank is DEGRADED", title="TrueNAS"),
        ntfy_line("M2", "container restarted unexpectedly", priority=4),
    )
    assert critical.rule == "signature:storage_degraded" and critical.effective == Route.NOTIFY_NOW
    assert high.proposed is Route.REVIEW  # fallback: priority >= 4 goes to Hermes review, never DROP
    kinds = [row["kind"] for row in outbox(app)]
    assert kinds == ["compose", "review"]
    assert outbox(app)[0]["critical"] == 1
    await app.close()


async def test_shadow_mode_records_without_delivery_or_digest(make_config, services):
    services.jev_default = jev_answers(harm=0.95)
    app = App(make_config(bridge__mode="shadow"), transport=services.transport())
    [decision] = await run(app, ntfy_line("M1", "ransomware note found on share"))
    assert decision.proposed is Route.NOTIFY_NOW
    assert decision.effective == "SHADOW"
    assert outbox(app) == []
    assert app.store.counts()["digest_pending"] == 0
    assert app.store.get_event("ntfy:alerts:M1")["status"] == "shadow"
    await app.close()


async def test_review_is_also_queued_for_digest(make_config, services):
    services.jev_default = jev_answers(digest=0.4, relevance=0.4)
    app = App(make_config(bridge__mode="full"), transport=services.transport())
    [decision] = await run(app, ntfy_line("M1", "something odd"))
    assert decision.effective == Route.REVIEW
    assert [row["kind"] for row in outbox(app)] == ["review"]
    assert app.store.digest_item_for("ntfy:alerts:M1") is not None
    await app.close()


async def test_repeat_within_cooldown_goes_to_digest(make_config, services):
    services.jev_default = jev_answers(harm=0.9)
    app = App(make_config(bridge__mode="full"), transport=services.transport())
    first, second = await run(app, ntfy_line("M1", "UPS on battery"), ntfy_line("M2", "UPS on battery"))
    assert first.effective == Route.NOTIFY_NOW
    assert second.event.repeat_bucket == "repeated"
    assert second.effective == Route.DIGEST
    assert any("cooldown" in r for r in second.reasons)
    await app.close()


async def test_echo_tags_drop_before_any_other_rule(make_config, services):
    app = App(make_config(bridge__mode="guarded"), transport=services.transport())
    [echo] = await run(app, ntfy_line("M1", "backup failed", tags=["hermes-bridge"]))
    assert echo.rule == "echo_tag" and echo.effective == Route.DROP
    assert services.jev_requests == []
    await app.close()


async def test_approved_fingerprints_drop_only_exact_matches(make_config, services, tmp_path):
    probe = App(make_config(bridge__database=str(tmp_path / "probe.db")), transport=services.transport())
    [heartbeat] = await run(probe, ntfy_line("P1", "nightly heartbeat ok", title="cron"))
    await probe.close()

    app = App(
        make_config(bridge__mode="guarded", policy__always_drop={"fingerprints": [heartbeat.event.fingerprint]}),
        transport=services.transport(),
    )
    exact, near = await run(
        app,
        ntfy_line("M1", "Nightly  heartbeat OK", title="cron"),  # case/whitespace-insensitive, otherwise exact
        ntfy_line("M2", "nightly heartbeat ok after 3 retries", title="cron"),
    )
    assert exact.rule == "approved_fingerprint" and exact.effective == Route.DROP
    assert near.rule is None and near.effective != Route.DROP
    await app.close()


def answers(category="informational", confidence=0.9, **noul) -> JevAnswers:
    base = {
        "immediate_harm_if_ignored": 0.1,
        "human_action_useful": 0.5,
        "digest_value": 0.5,
        "routine_noise": 0.3,
        "personal_relevance": 0.5,
    }
    return JevAnswers(category, confidence, {category: 1.0}, base | noul)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (answers(immediate_harm_if_ignored=0.80), Route.NOTIFY_NOW),
        (answers(immediate_harm_if_ignored=0.79), Route.REVIEW),
        (answers("security", 0.70), Route.NOTIFY_NOW),
        (answers("security", 0.69), Route.REVIEW),
        (answers("availability", 0.99), Route.REVIEW),
        (
            answers(routine_noise=0.90, immediate_harm_if_ignored=0.20, digest_value=0.35, personal_relevance=0.35),
            Route.DROP,
        ),
        (
            answers(routine_noise=0.90, immediate_harm_if_ignored=0.21, digest_value=0.35, personal_relevance=0.35),
            Route.REVIEW,
        ),
        (answers(routine_noise=0.95, digest_value=0.36, personal_relevance=0.1), Route.REVIEW),
        (answers(routine_noise=0.95, digest_value=0.7, personal_relevance=0.1), Route.DIGEST),
        (answers(personal_relevance=0.65), Route.DIGEST),
    ],
)
def test_threshold_policy(given, expected):
    assert route_from_answers(given, Thresholds())[0] is expected


@pytest.mark.parametrize(
    ("proposed", "mode", "deterministic", "drop_allowed", "expected"),
    [
        (Route.DROP, "guarded", False, True, Route.DIGEST),
        (Route.DROP, "guarded", True, False, Route.DROP),
        (Route.NOTIFY_NOW, "guarded", False, True, Route.REVIEW),
        (Route.NOTIFY_NOW, "guarded", True, True, Route.NOTIFY_NOW),
        (Route.DROP, "full", False, False, Route.DIGEST),
        (Route.DROP, "full", False, True, Route.DROP),
    ],
)
def test_rollout_gate(proposed, mode, deterministic, drop_allowed, expected):
    effective, _ = gate(proposed, mode=mode, deterministic=deterministic, drop_allowed=drop_allowed, synthetic=False)
    assert effective == expected


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("Backup job Photos completed successfully. 0 errors, 12 files uploaded.", None),
        ("Backup finished without errors", None),
        ("Backup job Photos failed: 3 errors", "signature:backup_failure"),
        ("Error during backup of /mnt/tank", "signature:backup_failure"),
        ("Pool tank state is DEGRADED", "signature:storage_degraded"),
        ("UPS ups0 on battery", "signature:power_event"),
    ],
)
def test_builtin_signatures(make_config, text, rule):
    from ntfy_hermes_bridge.models import CanonicalEvent
    from ntfy_hermes_bridge.policy import DeterministicPolicy

    event = CanonicalEvent(
        "ntfy:a:1", "homelab", "x", "notification", "", "", "a", 3, (), "", text, "", "", "generic-v1"
    )
    match = DeterministicPolicy(make_config()).evaluate(event)
    assert (match.rule if match else None) == rule


async def test_flapping_means_oscillation_not_changing_content(make_config, services):
    app = App(make_config(), transport=services.transport())
    churn = await run(app, *(ntfy_line(f"C{i}", f"price now {i}", title="shop") for i in range(5)))
    assert {d.event.repeat_bucket for d in churn} == {"first"}
    flaps = await run(app, *(ntfy_line(f"F{i}", ("down", "up")[i % 2], title="jellyfin") for i in range(4)))
    assert [d.event.repeat_bucket for d in flaps] == ["first", "first", "repeated", "flapping"]
    await app.close()
