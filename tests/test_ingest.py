import sqlite3

import httpx
import pytest

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


async def test_outbound_requests_to_unlisted_hosts_are_refused(make_config):
    app = App(make_config(), transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    with pytest.raises(httpx.TransportError, match="not allowed"):
        await app.http.get("http://example.com/")
    await app.close()
