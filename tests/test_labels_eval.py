import asyncio

import pytest

from ntfy_hermes_bridge.cli import main
from ntfy_hermes_bridge.daemon import App
from ntfy_hermes_bridge.models import Route

from .conftest import NTFY, jev_answers, ntfy_line

pytestmark = pytest.mark.anyio

NOISE = jev_answers(category="routine_success", noise=0.97, harm=0.05, digest=0.1, relevance=0.1)


async def run(app: App, *lines: str):
    for line in lines:
        app.ingest_line("alerts", line)
    return [await app.pipeline.process(row) for row in app.store.claim_received(100)]


def write_config(tmp_path, database: str, **policy) -> str:
    extra = "".join(f"{k} = {v}\n" for k, v in policy.items())
    path = tmp_path / "config.toml"
    path.write_text(
        f"""
[bridge]
mode = "full"
database = "{database}"
[ntfy]
base_url = "{NTFY}"
topics = [{{ name = "alerts", normalizer = "generic" }}]
[typesafe]
enabled = true
accept_cloud_data_boundary = true
[health]
listen = ""
[policy]
version = "test-1"
{extra}"""
    )
    return str(path)


async def test_relabeling_a_drop_is_stored_separately_and_blocks_drop(make_config, services, tmp_path):
    services.jev_default = NOISE
    config = make_config(bridge__mode="full", policy__min_labels_for_drop=1, policy__min_critical_labels_for_drop=0)
    app = App(config, transport=services.transport())
    [first] = await run(app, ntfy_line("M1", "disk check passed"))
    assert first.proposed is Route.DROP
    assert first.effective == Route.DIGEST  # no labels yet: guardrail keeps DROP off

    app.store.add_label("ntfy:alerts:M1", "NOTIFY_NOW", critical=True, note="was important")
    production = app.store.latest_decision("ntfy:alerts:M1")
    assert production["proposed_route"] == "DROP"  # the original decision is untouched
    assert [row["event_id"] for row in app.store.latest_labels()] == ["ntfy:alerts:M1"]
    assert app.config.policy.thresholds == make_config().policy.thresholds

    await app.refresh_guardrail()
    assert not app.ctx.guardrail.ok
    assert app.ctx.guardrail.critical_dropped == ("M1",)
    [later] = await run(app, ntfy_line("M2", "disk check passed again"))
    assert later.proposed is Route.DROP and later.effective == Route.DIGEST
    await app.close()

    # The evaluation dataset includes the relabeled event and fails the critical-recall gate.
    assert await asyncio.to_thread(main, ["-c", write_config(tmp_path, config.bridge.database), "eval"]) == 2


async def test_drop_activates_only_once_guardrail_passes(make_config, services):
    services.jev_default = NOISE
    config = make_config(bridge__mode="full", policy__min_labels_for_drop=1, policy__min_critical_labels_for_drop=0)
    app = App(config, transport=services.transport())
    await run(app, ntfy_line("M1", "heartbeat ok"))
    app.store.add_label("ntfy:alerts:M1", "DROP", critical=False, note="")
    await app.refresh_guardrail()
    assert app.ctx.guardrail.ok
    [decision] = await run(app, ntfy_line("M2", "another heartbeat"))
    assert decision.effective == Route.DROP
    assert app.store.get_event("ntfy:alerts:M2")["status"] == "dropped"
    await app.close()


async def test_candidate_policy_regressions_are_reported(make_config, services, tmp_path, capsys):
    services.jev_default = jev_answers(harm=0.85)
    config = make_config(bridge__mode="full")
    app = App(config, transport=services.transport())
    await run(app, ntfy_line("M1", "replication task failed"))
    app.store.add_label("ntfy:alerts:M1", "NOTIFY_NOW", critical=True, note="")
    await app.close()

    current = write_config(tmp_path, config.bridge.database)
    candidate_dir = tmp_path / "candidate"
    candidate_dir.mkdir()
    candidate = write_config(candidate_dir, config.bridge.database, **{"thresholds": "{ notify_harm = 0.9 }"})
    assert await asyncio.to_thread(main, ["-c", current, "eval", "--candidate", candidate]) == 2
    out = capsys.readouterr().out
    assert "regression CRITICAL: ntfy:alerts:M1 label NOTIFY_NOW · NOTIFY_NOW -> REVIEW" in out
