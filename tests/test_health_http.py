import asyncio
import json

import pytest

import ntfy_hermes_bridge.daemon as daemon_module
from ntfy_hermes_bridge.daemon import App

pytestmark = pytest.mark.anyio


async def start_health_server(app: App) -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(app._handle_health_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def request(port: int, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


async def test_health_and_metrics_endpoints_keep_existing_behavior(make_config, services):
    app = App(make_config(), transport=services.transport())
    server, port = await start_health_server(app)
    async with server:
        health = await request(port, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        metrics = await request(port, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")

    status, body = health.split(b"\r\n\r\n", 1)
    assert status.startswith(b"HTTP/1.1 200 OK")
    assert json.loads(body)["status"] == "ok"
    assert metrics.startswith(b"HTTP/1.1 200 OK")
    assert b"ntfy_bridge_events_nonterminal" in metrics
    await app.close()


async def test_bad_or_oversized_requests_are_rejected_without_stopping_server(make_config, services):
    app = App(make_config(), transport=services.transport())
    server, port = await start_health_server(app)
    async with server:
        too_many_headers = b"GET /healthz HTTP/1.1\r\n" + b"X-Test: value\r\n" * 65 + b"\r\n"
        oversized = await request(port, too_many_headers)
        non_ascii = await request(port, b"GET /\xff HTTP/1.1\r\n\r\n")
        long_request_line = await request(
            port,
            b"GET /" + b"x" * daemon_module.HEALTH_MAX_REQUEST_LINE_BYTES + b" HTTP/1.1\r\n\r\n",
        )
        healthy = await request(port, b"GET /healthz HTTP/1.1\r\n\r\n")

    assert oversized.startswith(b"HTTP/1.1 431 Request Header Fields Too Large")
    assert non_ascii.startswith(b"HTTP/1.1 400 Bad Request")
    assert long_request_line.startswith(b"HTTP/1.1 400 Bad Request")
    assert healthy.startswith(b"HTTP/1.1 200 OK")
    await app.close()


async def test_request_timeout_is_one_deadline_for_the_entire_parse(make_config, services, monkeypatch):
    monkeypatch.setattr(daemon_module, "HEALTH_REQUEST_TIMEOUT_SECONDS", 0.3)
    app = App(make_config(), transport=services.transport())
    server, port = await start_health_server(app)
    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET /healthz HTTP/1.1\r\n")
        await writer.drain()
        await asyncio.sleep(0.18)
        writer.write(b"Host: localhost\r\n")
        await writer.drain()
        await asyncio.sleep(0.18)
        assert await asyncio.wait_for(reader.read(), timeout=0.5) == b""
        writer.close()
        await writer.wait_closed()

        healthy = await request(port, b"GET /healthz HTTP/1.1\r\n\r\n")

    assert healthy.startswith(b"HTTP/1.1 200 OK")
    await app.close()
