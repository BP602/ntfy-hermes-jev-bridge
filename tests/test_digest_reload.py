import json
from datetime import UTC, datetime

import pytest

from ntfy_hermes_bridge.daemon import App
from ntfy_hermes_bridge.digest import run_due_digest
from ntfy_hermes_bridge.hermes import encode

from .conftest import jev_answers, ntfy_line

pytestmark = pytest.mark.anyio


async def run(app: App, *lines: str):
    for line in lines:
        app.ingest_line("alerts", line)
    return [await app.pipeline.process(row) for row in app.store.claim_received(500)]


def digests(app: App) -> list[dict]:
    rows = app.store.conn.execute("SELECT payload_json FROM outbox WHERE kind = 'digest' ORDER BY id").fetchall()
    return [json.loads(r["payload_json"]) for r in rows]


async def test_digest_collapses_duplicates_and_resolved_flaps(make_config, services):
    app = App(make_config(bridge__mode="full", policy__cooldown_seconds=0), transport=services.transport())
    services.jev = [
        jev_answers(category="maintenance", digest=0.8),
        jev_answers(category="maintenance", digest=0.8),
        jev_answers(category="availability", digest=0.8),
        jev_answers(category="recovery", digest=0.8),
    ]
    await run(
        app,
        ntfy_line("M1", "Immich updated to 1.2", title="immich"),
        ntfy_line("M2", "Immich updated to 1.2", title="immich"),
        ntfy_line("M3", "jellyfin down", title="jellyfin"),
        ntfy_line("M4", "jellyfin up", title="jellyfin"),
    )
    assert run_due_digest(app.store, app.config, datetime.now(UTC), force=True) == 1
    [payload] = digests(app)
    groups = {g["category"]: g for g in payload["groups"]}
    [update] = groups["maintenance"]["items"]
    assert update["count"] == 2
    [flap] = groups["resolved_transients"]["items"]
    assert flap["entity"] == "jellyfin" and flap["failures"] == 1
    assert payload["event_count"] == 4
    assert app.store.counts()["digest_pending"] == 0
    await app.close()


async def test_large_digest_is_split_under_body_limit(make_config, services):
    services.jev_default = jev_answers(digest=0.9)
    config = make_config(bridge__mode="full", hermes__max_body_bytes=16_384, digest__item_excerpt_chars=280)
    app = App(config, transport=services.transport())
    await run(app, *(ntfy_line(f"M{i}", f"update {i} " + "z" * 400, title=f"svc{i}") for i in range(120)))
    run_due_digest(app.store, app.config, datetime.now(UTC), force=True)
    parts = digests(app)
    assert len(parts) > 1
    assert all(len(encode(p)) <= 16_384 for p in parts)
    assert {p["parts"] for p in parts} == {len(parts)}
    assert sum(p["event_count"] for p in parts) == 120
    await app.close()


async def test_scheduled_digest_runs_once_per_slot(make_config, services):
    app = App(make_config(bridge__mode="full", digest__schedule=["08:00"]), transport=services.transport())
    services.jev_default = jev_answers(digest=0.9)
    await run(app, ntfy_line("M1", "update available"))
    day1 = datetime(2026, 9, 24, 7, 0, tzinfo=UTC)
    assert run_due_digest(app.store, app.config, day1) == 0  # first start only records the slot
    assert run_due_digest(app.store, app.config, day1.replace(hour=9)) == 1
    assert run_due_digest(app.store, app.config, day1.replace(hour=10)) == 0
    await app.close()


async def test_hot_reload_applies_valid_policy_and_rejects_invalid(tmp_path, services):
    path = tmp_path / "config.toml"
    base = f"""
[bridge]
database = "{tmp_path / "b.db"}"
[ntfy]
base_url = "http://127.0.0.1:2586"
topics = [{{ name = "alerts" }}]
[health]
listen = ""
[policy]
version = "%s"
"""
    path.write_text(base % "v1")
    from ntfy_hermes_bridge.config import load_config

    app = App(load_config(path), config_path=path, transport=services.transport())
    path.write_text(base % "v2")
    app.config_mtime = 0
    assert await app.maybe_reload()
    assert app.config.policy.version == "v2"

    path.write_text(base % "v3" + "[policy.thresholds]\nnotify_harm = 7\n")
    app.config_mtime = 0
    assert not await app.maybe_reload()
    assert app.config.policy.version == "v2"

    path.write_text((base % "v4").replace("2586", "2587"))
    app.config_mtime = 0
    assert not await app.maybe_reload()  # endpoint change needs a restart
    await app.close()
