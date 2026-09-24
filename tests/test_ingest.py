import sqlite3

import httpx
import pytest

from ntfy_hermes_bridge.config import load_config
from ntfy_hermes_bridge.daemon import App

from .conftest import ntfy_line

pytestmark = pytest.mark.anyio


class NtfyStream:
    def __init__(self, *batches: list[str]):
        self.batches = list(batches)
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/alerts/json"
        self.requests.append(request)
        lines = self.batches.pop(0)
        return httpx.Response(200, content=("\n".join(lines) + "\n").encode())


async def test_reconnect_replays_since_cursor_and_persists_once(make_config):
    open_line = '{"id":"o1","time":1,"event":"open","topic":"alerts"}'
    keepalive = '{"id":"k1","time":2,"event":"keepalive","topic":"alerts"}'
    ntfy = NtfyStream(
        [open_line, ntfy_line("M1")],
        # after reconnect ntfy may resend overlap; M1 must not be persisted twice
        [open_line, ntfy_line("M1"), ntfy_line("M2"), keepalive, ntfy_line("M3")],
    )
    app = App(make_config(), transport=httpx.MockTransport(ntfy.handler))
    topic = app.config.ntfy.topics[0]

    await app.stream_once(topic)
    assert "since" not in ntfy.requests[0].url.params
    assert app.store.get_cursor("alerts") == "M1"

    await app.stream_once(topic)
    assert ntfy.requests[1].url.params["since"] == "M1"
    rows = app.store.conn.execute("SELECT message_id FROM events ORDER BY message_id").fetchall()
    assert [r["message_id"] for r in rows] == ["M1", "M2", "M3"]
    assert app.store.get_cursor("alerts") == "M3"
    await app.close()


async def test_truncated_replay_alert_is_deduplicated_until_a_clean_replay(make_config):
    truncated = iter((True, True, False, True))

    def handler(request: httpx.Request) -> httpx.Response:
        headers = {"X-Messages-Truncated": "1"} if next(truncated) else {}
        return httpx.Response(200, headers=headers, content=b"")

    app = App(make_config(), transport=httpx.MockTransport(handler))
    topic = app.config.ntfy.topics[0]

    def alert_count() -> int:
        return app.store.conn.execute(
            "SELECT COUNT(*) AS n FROM events WHERE event_id LIKE 'bridge:replay_truncated:%'"
        ).fetchone()["n"]

    await app.stream_once(topic)
    await app.stream_once(topic)
    assert alert_count() == 1

    await app.stream_once(topic)
    await app.stream_once(topic)
    assert alert_count() == 2
    assert app.metrics.value("health_alerts_total", kind="replay_truncated") == 2
    await app.close()


async def test_cursor_does_not_advance_when_persistence_fails(make_config):
    ntfy = NtfyStream([ntfy_line("M1"), ntfy_line("M2")])
    app = App(make_config(), transport=httpx.MockTransport(ntfy.handler))
    app.store.conn.execute(
        "CREATE TRIGGER fail_m2 BEFORE INSERT ON events WHEN NEW.message_id = 'M2' "
        "BEGIN SELECT RAISE(ABORT, 'disk full'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        await app.stream_once(app.config.ntfy.topics[0])
    assert app.store.get_cursor("alerts") == "M1"
    await app.close()


async def test_malformed_lines_are_quarantined_without_stopping_the_stream(make_config):
    ntfy = NtfyStream(["not json", '{"event":"message","message":"no id"}', ntfy_line("M1")])
    app = App(make_config(), transport=httpx.MockTransport(ntfy.handler))
    await app.stream_once(app.config.ntfy.topics[0])
    assert app.store.counts()["quarantine_raw"] == 2
    assert app.store.get_event("ntfy:alerts:M1") is not None
    await app.close()


async def test_invalid_timestamps_fall_back_to_received_time_without_stopping_stream(make_config):
    lines = [
        '{"id":"M1","time":1e30,"event":"message","topic":"alerts","message":"far future"}',
        '{"id":"M2","time":-1e30,"event":"message","topic":"alerts","message":"far past"}',
        '{"id":"M3","time":NaN,"event":"message","topic":"alerts","message":"not a number"}',
        '{"id":"M4","time":Infinity,"event":"message","topic":"alerts","message":"positive infinity"}',
        '{"id":"M5","time":-Infinity,"event":"message","topic":"alerts","message":"negative infinity"}',
    ]
    ntfy = NtfyStream(lines)
    app = App(make_config(), transport=httpx.MockTransport(ntfy.handler))

    await app.stream_once(app.config.ntfy.topics[0])

    rows = app.store.conn.execute(
        "SELECT message_id, raw_json, occurred_at, received_at FROM events ORDER BY rowid"
    ).fetchall()
    assert [row["message_id"] for row in rows] == ["M1", "M2", "M3", "M4", "M5"]
    assert [row["raw_json"] for row in rows] == lines
    assert all(row["occurred_at"] == row["received_at"] for row in rows)
    cursor = app.store.conn.execute("SELECT message_id, message_time FROM cursors WHERE topic = 'alerts'").fetchone()
    assert (cursor["message_id"], cursor["message_time"]) == ("M5", 0)
    await app.close()


async def test_hot_reload_rejects_promotion_without_resolved_hermes_secret(tmp_path, services, monkeypatch, caplog):
    path = tmp_path / "config.toml"

    def config_text(mode: str, version: str) -> str:
        return f"""
[bridge]
mode = "{mode}"
database = "{tmp_path / "reload.db"}"
[ntfy]
base_url = "http://127.0.0.1:2586"
topics = [{{ name = "alerts" }}]
[health]
listen = ""
[policy]
version = "{version}"
"""

    monkeypatch.delenv("HERMES_WEBHOOK_SECRET")
    path.write_text(config_text("shadow", "v1"))
    app = App(load_config(path), config_path=path, transport=services.transport())
    active = app.config

    path.write_text(config_text("guarded", "v2"))
    app.config_mtime = 0
    assert not await app.maybe_reload()
    assert app.config is active
    assert app.config.bridge.mode == "shadow"
    assert app.config.policy.version == "v1"
    [rejection] = [record for record in caplog.records if record.message == "config reload rejected: invalid"]
    assert rejection.keeping_policy == "v1"
    assert rejection.error == "mode 'guarded' requires $HERMES_WEBHOOK_SECRET for signed Hermes delivery"
    await app.close()


async def test_outbound_requests_to_unlisted_hosts_are_refused(make_config):
    app = App(make_config(), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(httpx.TransportError, match="not allowed"):
        await app.http.get("http://example.com/")
    await app.close()
