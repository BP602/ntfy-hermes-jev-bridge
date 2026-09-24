"""Long-running bridge: ntfy subscribers, classifier workers, outbox, digests, health, and hot reload."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import random
import signal
import sqlite3
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from . import BUILD
from .config import Config, ConfigError, TopicSettings, load_config, secret, tls_context
from .digest import run_due_digest
from .hermes import HermesClient, fallback_ntfy_payload, publish_ntfy
from .jev import JevClient
from .logs import setup_logging
from .metrics import Metrics
from .models import INTERNAL_EVENT_PREFIX, iso_from_unix, now_iso
from .normalize import MESSAGE_ID_RE
from .pipeline import Context, Pipeline
from .store import OutboxInsert, Store

log = logging.getLogger(__name__)

GUARDRAIL_REFRESH_SECONDS = 600
RELOAD_POLL_SECONDS = 5
PRUNE_INTERVAL_SECONDS = 86_400
MIN_UNIX_TIMESTAMP = -62_135_596_800
MAX_UNIX_TIMESTAMP = 253_402_300_799
LOOP_RETRY_SECONDS = 1.0
HEALTH_REQUEST_TIMEOUT_SECONDS = 5.0
HEALTH_MAX_REQUEST_LINE_BYTES = 8_192
HEALTH_MAX_HEADER_COUNT = 64
HEALTH_MAX_HEADER_BYTES = 16_384


class DestinationDenied(httpx.TransportError):
    pass


def make_http(config: Config, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    """HTTP client that refuses any destination outside the configured allowlist (default deny)."""
    allowed_hosts = config.allowed_hosts()

    async def enforce(request: httpx.Request) -> None:
        if request.url.host not in allowed_hosts:
            raise DestinationDenied(f"outbound destination {request.url.host!r} is not allowed", request=request)

    # HTTP/2 (negotiated via ALPN on HTTPS only): reverse proxies such as Nginx Proxy Manager can buffer
    # HTTP/1.1 ntfy streams until close, while HTTP/2 responses are passed through as they arrive.
    return httpx.AsyncClient(
        follow_redirects=False,
        event_hooks={"request": [enforce]},
        transport=transport,
        http2=True,
        verify=tls_context(config.network),
    )


class App:
    def __init__(
        self, config: Config, *, config_path: Path | None = None, transport: httpx.AsyncBaseTransport | None = None
    ):
        self.config_path = config_path
        self.config_mtime = config_path.stat().st_mtime if config_path else 0.0
        self.store = Store(config.bridge.database)
        self.metrics = Metrics()
        self.http = make_http(config, transport)
        self.ntfy_token = secret(config.ntfy.token_env)
        jev = None
        if config.typesafe.enabled:
            api_key = secret(config.typesafe.api_key_env)
            if not api_key:
                raise ConfigError(f"typesafe.enabled but ${config.typesafe.api_key_env} is empty")
            jev = JevClient(self.http, api_key)
        hermes_secret = secret(config.hermes.secret_env)
        if config.bridge.mode != "shadow" and not hermes_secret:
            raise ConfigError(
                f"mode {config.bridge.mode!r} requires ${config.hermes.secret_env} for signed Hermes delivery"
            )
        self.hermes = HermesClient(self.http, hermes_secret)
        self.pipeline = Pipeline(self.store, self.metrics, jev, Context.build(config))
        self.wake = asyncio.Event()
        self.outbox_wake = asyncio.Event()
        self.connected: dict[str, bool] = {t.name: False for t in config.ntfy.topics}
        self.disconnected_since: dict[str, float] = {t.name: time.monotonic() for t in config.ntfy.topics}
        self.alerts_active: set[str] = set()
        self.last_quarantine_count = self.store.counts()["quarantine_raw"]
        self.started = time.monotonic()

    @property
    def ctx(self) -> Context:
        return self.pipeline.ctx

    @property
    def config(self) -> Config:
        return self.pipeline.ctx.config

    async def close(self) -> None:
        await self.http.aclose()
        self.store.close()

    # ---- run --------------------------------------------------------------------------------

    async def run(self) -> None:
        reset = self.store.reset_processing()
        if reset:
            log.info("resuming events interrupted mid-processing", extra={"count": reset})
        await self.refresh_guardrail()
        log.info(
            "bridge starting",
            extra={
                "version": BUILD,
                "mode": self.config.bridge.mode,
                "policy_version": self.config.policy.version,
                "policy_hash": self.ctx.policy_hash,
                "jev_model": self.config.typesafe.model if self.config.typesafe.enabled else None,
                "topics": list(self.connected),
            },
        )
        async with asyncio.TaskGroup() as tg:
            for topic in self.config.ntfy.topics:
                tg.create_task(self.subscribe(topic), name=f"ntfy:{topic.name}")
            tg.create_task(self.process_loop(), name="processor")
            tg.create_task(self.outbox_loop(), name="outbox")
            tg.create_task(self.digest_loop(), name="digest")
            tg.create_task(self.health_loop(), name="health")
            tg.create_task(self.maintenance_loop(), name="maintenance")
            if self.config_path:
                tg.create_task(self.reload_loop(), name="reload")
            if self.config.health.listen:
                tg.create_task(self.serve_http(), name="http")

    # ---- ntfy ingestion ---------------------------------------------------------------------

    async def subscribe(self, topic: TopicSettings) -> None:
        backoff = 1.0
        while True:
            try:
                await self.stream_once(topic)
                backoff = 1.0
            except (httpx.HTTPError, ConnectionError) as exc:
                log.warning("ntfy stream error", extra={"topic": topic.name, "error": str(exc) or type(exc).__name__})
            self._set_connected(topic.name, False)
            await asyncio.sleep(backoff * random.uniform(0.8, 1.2))
            backoff = min(backoff * 2, self.config.ntfy.reconnect_max_seconds)

    async def stream_once(self, topic: TopicSettings) -> None:
        ntfy = self.config.ntfy
        params = {}
        cursor = self.store.get_cursor(topic.name)
        if cursor:
            params["since"] = cursor
        elif ntfy.initial_since:
            params["since"] = ntfy.initial_since
        headers = {"Authorization": f"Bearer {self.ntfy_token}"} if self.ntfy_token else {}
        url = f"{ntfy.base_url.rstrip('/')}/{topic.name}/json"
        timeout = httpx.Timeout(10.0, read=ntfy.read_timeout_seconds)
        async with self.http.stream("GET", url, params=params, headers=headers, timeout=timeout) as response:
            if response.status_code != 200:
                raise httpx.HTTPStatusError(f"HTTP {response.status_code}", request=response.request, response=response)
            truncated = response.headers.get("x-messages-truncated") == "1"
            self.check_alert(
                "replay_truncated",
                truncated,
                f"ntfy replay for topic {topic.name} was truncated; older cached messages were lost",
                key=f"replay_truncated:{topic.name}",
            )
            if truncated:
                self.metrics.inc("ntfy_truncated_replays_total", topic=topic.name)
                log.error("ntfy replay truncated; older cached messages were lost", extra={"topic": topic.name})
            self._set_connected(topic.name, True)
            log.info("ntfy connected", extra={"topic": topic.name, "since": params.get("since", "now")})
            async for line in response.aiter_lines():
                if line.strip():
                    self.ingest_line(topic.name, line)

    def ingest_line(self, topic: str, line: str) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            self.store.quarantine_raw(topic, line, "invalid JSON")
            self.metrics.inc("events_quarantined_total")
            return
        if not isinstance(msg, dict):
            self.store.quarantine_raw(topic, line, "not a JSON object")
            self.metrics.inc("events_quarantined_total")
            return
        if msg.get("event") != "message":
            return
        mid = msg.get("id")
        if not isinstance(mid, str) or not MESSAGE_ID_RE.match(mid):
            self.store.quarantine_raw(topic, line, "missing or invalid message id")
            self.metrics.inc("events_quarantined_total")
            return
        received = now_iso()
        stamp = msg.get("time")
        valid_time = (
            isinstance(stamp, (int, float))
            and not isinstance(stamp, bool)
            and MIN_UNIX_TIMESTAMP <= stamp <= MAX_UNIX_TIMESTAMP
        )
        inserted = self.store.ingest(
            topic=topic,
            message_id=mid,
            message_time=int(stamp) if valid_time else 0,
            raw_json=line,
            occurred_at=iso_from_unix(stamp) if valid_time else received,
            received_at=received,
        )
        if inserted:
            self.metrics.inc("events_ingested_total", topic=topic)
            self.wake.set()
        else:
            self.metrics.inc("events_duplicate_total", topic=topic)

    def _set_connected(self, topic: str, connected: bool) -> None:
        if self.connected.get(topic) and not connected:
            self.disconnected_since[topic] = time.monotonic()
        self.connected[topic] = connected

    # ---- classification ---------------------------------------------------------------------

    async def process_loop(self) -> None:
        workers = self.config.bridge.workers
        inflight: set[asyncio.Task] = set()
        while True:
            self.wake.clear()
            free = workers - len(inflight)
            rows = self.store.claim_received(free) if free > 0 else []
            for row in rows:
                task = asyncio.create_task(self.process_one(row))
                inflight.add(task)
                task.add_done_callback(lambda t: (inflight.discard(t), self.wake.set()))
            if len(rows) < free or free <= 0:
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.wake.wait(), timeout=5)

    async def process_one(self, row: sqlite3.Row) -> None:
        try:
            decision = await self.pipeline.process(row)
        except Exception as exc:  # keep the pipeline alive; the event stays in the inbox
            status = self.store.release_failed(row["event_id"], f"{type(exc).__name__}: {exc}")
            log.exception("event processing failed", extra={"event_id": row["event_id"], "status": status})
            return
        if decision is not None:
            log.info(
                "event decided",
                extra={
                    "event_id": decision.event.event_id,
                    "source": decision.event.source,
                    "event_kind": decision.event.event_kind,
                    "proposed": str(decision.proposed),
                    "effective": str(decision.effective),
                    "rule": decision.rule,
                    "jev_model": decision.jev.model if decision.jev else None,
                    "jev_error": decision.jev_error,
                },
            )
            if decision.effective in ("NOTIFY_NOW", "REVIEW"):
                self.outbox_wake.set()

    async def refresh_guardrail(self) -> None:
        ctx = self.ctx
        ctx.guardrail = await self.pipeline.compute_guardrail(ctx)
        if ctx.config.bridge.mode == "full":
            log.info("drop guardrail", extra={"ok": ctx.guardrail.ok, "detail": ctx.guardrail.describe()})

    # ---- delivery ---------------------------------------------------------------------------

    async def outbox_loop(self) -> None:
        while True:
            try:
                self.outbox_wake.clear()
                rows = self.store.due_outbox(now_iso(), self.config.outbox.concurrency)
                if rows:
                    delivered = await asyncio.gather(*(self._deliver_safely(row) for row in rows))
                    if not all(delivered):
                        await asyncio.sleep(LOOP_RETRY_SECONDS)
                    continue
                due = self.store.next_outbox_due()
                wait = 5.0  # also picks up work enqueued by the CLI (digest flush, outbox retry)
                if due:
                    wait = max(0.05, min(wait, (datetime.fromisoformat(due) - datetime.now(UTC)).total_seconds()))
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self.outbox_wake.wait(), timeout=wait)
            except Exception:
                log.exception("outbox loop iteration failed; will retry")
                await asyncio.sleep(LOOP_RETRY_SECONDS)

    async def _deliver_safely(self, row: sqlite3.Row) -> bool:
        try:
            await self.deliver(row)
        except Exception:
            log.exception("delivery attempt failed unexpectedly", extra={"outbox_id": row["id"]})
            return False
        return True

    async def deliver(self, row: sqlite3.Row) -> None:
        config = self.config
        payload = json.loads(row["payload_json"])
        kind = row["kind"]
        if kind == "fallback_ntfy":
            outcome = await publish_ntfy(
                self.http, config.ntfy.base_url, self.ntfy_token, payload, timeout=config.hermes.timeout_seconds
            )
        else:
            route = {
                "compose": config.hermes.compose_route,
                "review": config.hermes.review_route,
                "digest": config.hermes.digest_route,
            }[kind]
            outcome = await self.hermes.post(
                config.hermes.base_url,
                route,
                payload,
                request_id=row["request_id"],
                timeout=config.hermes.timeout_seconds,
            )
        attempts = row["attempts"] + 1
        if outcome.ok:
            self.store.outbox_delivered(row)
            self.metrics.inc("deliveries_total", kind=kind, outcome="delivered")
            log.info("delivered", extra={"outbox_id": row["id"], "kind": kind, "request_id": row["request_id"]})
            return
        if not outcome.retryable or attempts >= config.outbox.max_attempts:
            self.store.outbox_dead(row, error=outcome.detail)
            self.metrics.inc("deliveries_total", kind=kind, outcome="dead")
            log.error(
                "delivery dead-lettered",
                extra={
                    "outbox_id": row["id"],
                    "kind": kind,
                    "request_id": row["request_id"],
                    "attempts": attempts,
                    "error": outcome.detail,
                },
            )
        else:
            delay = min(config.outbox.max_backoff_seconds, config.outbox.base_backoff_seconds * 2 ** (attempts - 1))
            due = (datetime.now(UTC) + timedelta(seconds=delay * random.uniform(0.8, 1.2))).isoformat(
                timespec="microseconds"
            )
            self.store.outbox_retry(row["id"], error=outcome.detail, next_attempt_at=due)
            self.metrics.inc("deliveries_total", kind=kind, outcome="retry")
            log.warning(
                "delivery failed; will retry",
                extra={
                    "outbox_id": row["id"],
                    "kind": kind,
                    "request_id": row["request_id"],
                    "attempts": attempts,
                    "next_attempt_at": due,
                    "error": outcome.detail,
                },
            )
        if (
            kind == "compose"
            and row["critical"]
            and config.fallback.ntfy_topic
            and (attempts >= config.fallback.after_attempts or not outcome.retryable)
        ):
            self.enqueue_fallback(row, payload)

    def enqueue_fallback(self, row: sqlite3.Row, payload: dict) -> None:
        config = self.config
        item = OutboxInsert(
            "fallback_ntfy",
            request_id=f"fallback:{row['request_id']}",
            payload=fallback_ntfy_payload(
                payload, topic=config.fallback.ntfy_topic, echo_tag=config.policy.echo_tags[0]
            ),
            critical=True,
        )
        if self.store.enqueue(item, event_id=row["event_id"]):
            log.warning(
                "Hermes unavailable for critical event; queued clean-ntfy fallback",
                extra={"request_id": row["request_id"]},
            )
            self.outbox_wake.set()

    # ---- digests ----------------------------------------------------------------------------

    async def digest_loop(self) -> None:
        while True:
            try:
                parts = run_due_digest(self.store, self.config, datetime.now(UTC))
                if parts:
                    self.metrics.inc("digests_total", parts)
                    log.info("digest enqueued", extra={"parts": parts})
                    self.outbox_wake.set()
            except Exception:
                log.exception("digest loop iteration failed; will retry")
            await asyncio.sleep(30)

    # ---- health -----------------------------------------------------------------------------

    def health(self) -> dict:
        counts = self.store.counts()
        now = time.monotonic()
        outage = self.config.health.ingest_outage_seconds
        ingest_down = [t for t, up in self.connected.items() if not up and now - self.disconnected_since[t] > outage]
        delivery_down = counts["outbox_oldest_pending_seconds"] > self.config.health.delivery_outage_seconds
        events_stalled = counts["events_nonterminal"] > 0 and counts["events_oldest_nonterminal_seconds"] > 86_400
        status = (
            "ok"
            if not ingest_down and not delivery_down and not counts["outbox_dead"] and not events_stalled
            else "degraded"
        )
        return {
            "status": status,
            "version": BUILD,
            "mode": self.config.bridge.mode,
            "policy_version": self.config.policy.version,
            "policy_hash": self.ctx.policy_hash,
            "jev_model": self.config.typesafe.model if self.config.typesafe.enabled else None,
            "drop_guardrail": self.ctx.guardrail.describe(),
            "topics": {t: ("connected" if up else "disconnected") for t, up in self.connected.items()},
            "ingest_outage_topics": ingest_down,
            "delivery_outage": delivery_down,
            "events_stalled": events_stalled,
            **counts,
        }

    async def health_loop(self) -> None:
        while True:
            await asyncio.sleep(15)
            self._check_health_alerts(self.health())

    def _check_health_alerts(self, snapshot: dict) -> None:
        self.check_alert(
            "ingest_outage",
            bool(snapshot["ingest_outage_topics"]),
            f"ntfy ingestion down for topics {', '.join(snapshot['ingest_outage_topics'])} "
            f"(> {self.config.health.ingest_outage_seconds}s)",
        )
        self.check_alert(
            "delivery_outage",
            snapshot["delivery_outage"] or snapshot["outbox_dead"] > 0,
            f"Hermes delivery degraded: {snapshot['outbox_pending']} pending "
            f"(oldest {snapshot['outbox_oldest_pending_seconds']:.0f}s), {snapshot['outbox_dead']} dead letters",
        )
        quarantine_count = snapshot["quarantine_raw"]
        quarantine_growth = quarantine_count > self.last_quarantine_count
        self.check_alert(
            "quarantine_growth",
            quarantine_growth,
            f"Malformed ntfy input quarantine grew from {self.last_quarantine_count} to {quarantine_count}",
        )
        self.last_quarantine_count = quarantine_count
        self.check_alert(
            "events_stalled",
            snapshot["events_stalled"],
            f"Event processing backlog stalled: {snapshot['events_nonterminal']} nonterminal events "
            f"(oldest {snapshot['events_oldest_nonterminal_seconds']:.0f}s)",
        )

    def check_alert(self, kind: str, active: bool, message: str, *, key: str | None = None) -> None:
        """Raise one bridge-health event per outage; re-arm once the condition clears."""
        alert_key = key or kind
        if not active:
            self.alerts_active.discard(alert_key)
            return
        if alert_key in self.alerts_active:
            return
        self.raise_internal_event(kind, message)
        self.alerts_active.add(alert_key)
        self.metrics.inc("health_alerts_total", kind=kind)

    def raise_internal_event(self, kind: str, message: str) -> None:
        mid = uuid.uuid4().hex[:16]
        now = time.time()
        raw = {
            "id": mid,
            "time": int(now),
            "event": "message",
            "topic": "_bridge",
            "title": f"ntfy bridge: {kind.replace('_', ' ')}",
            "message": message,
            "priority": 5,
            "tags": ["bridge-health", kind],
        }
        self.store.ingest(
            topic="_bridge",
            message_id=mid,
            message_time=int(now),
            raw_json=json.dumps(raw),
            occurred_at=iso_from_unix(now),
            received_at=now_iso(),
            advance_cursor=False,
            event_id=f"{INTERNAL_EVENT_PREFIX}{kind}:{mid}",
        )
        log.error("bridge health alert", extra={"alert": kind, "detail": message})
        self.wake.set()

    async def _read_health_request(self, reader: asyncio.StreamReader) -> str:
        async with asyncio.timeout(HEALTH_REQUEST_TIMEOUT_SECONDS):
            request_line = await reader.readline()
            if not request_line or len(request_line) > HEALTH_MAX_REQUEST_LINE_BYTES:
                raise ValueError("invalid request line")
            parts = request_line.decode("ascii").split()
            if len(parts) != 3 or not parts[2].startswith("HTTP/"):
                raise ValueError("invalid request line")

            header_count = 0
            header_bytes = 0
            while True:
                try:
                    line = await reader.readline()
                except ValueError as exc:
                    raise OverflowError("header line too large") from exc
                if line in (b"\r\n", b"\n"):
                    return parts[1]
                if not line:
                    raise ValueError("incomplete headers")
                header_count += 1
                header_bytes += len(line)
                if header_count > HEALTH_MAX_HEADER_COUNT or header_bytes > HEALTH_MAX_HEADER_BYTES:
                    raise OverflowError("headers too large")

    async def _write_health_response(self, writer: asyncio.StreamWriter, status: str, ctype: str, body: bytes) -> None:
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()

    async def _handle_health_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                path = await self._read_health_request(reader)
            except OverflowError:
                await self._write_health_response(
                    writer, "431 Request Header Fields Too Large", "text/plain", b"headers too large\n"
                )
                return
            except (ValueError, UnicodeError):
                await self._write_health_response(writer, "400 Bad Request", "text/plain", b"bad request\n")
                return
            except TimeoutError:
                return

            if path.startswith("/metrics"):
                body = self.metrics.render(self.store.counts()).encode()
                status, ctype = "200 OK", "text/plain; version=0.0.4"
            elif path.startswith("/healthz") or path == "/":
                snapshot = self.health()
                body = json.dumps(snapshot).encode()
                status = "200 OK" if snapshot["status"] == "ok" else "503 Service Unavailable"
                ctype = "application/json"
            else:
                body, status, ctype = b"not found\n", "404 Not Found", "text/plain"
            await self._write_health_response(writer, status, ctype, body)
        except ConnectionError:
            pass
        except Exception:
            log.exception("health HTTP request failed")
            with contextlib.suppress(Exception):
                await self._write_health_response(
                    writer, "500 Internal Server Error", "text/plain", b"internal server error\n"
                )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def serve_http(self) -> None:
        host, port = self.config.health.listen.rsplit(":", 1)
        server = await asyncio.start_server(self._handle_health_client, host, int(port))
        log.info("health/metrics listening", extra={"url": f"http://{host}:{port}"})
        async with server:
            await server.serve_forever()

    # ---- maintenance / reload ---------------------------------------------------------------

    async def maintenance_loop(self) -> None:
        last_prune = 0.0
        while True:
            await asyncio.sleep(GUARDRAIL_REFRESH_SECONDS)
            try:
                await self.refresh_guardrail()
                if time.monotonic() - last_prune > PRUNE_INTERVAL_SECONDS:
                    pruned = self.store.prune(self.config.retention.days)
                    last_prune = time.monotonic()
                    if pruned:
                        log.info("retention prune", extra={"events": pruned, "days": self.config.retention.days})
            except Exception:
                log.exception("maintenance loop iteration failed; will retry")

    async def reload_loop(self) -> None:
        while True:
            await asyncio.sleep(RELOAD_POLL_SECONDS)
            await self.maybe_reload()

    async def maybe_reload(self) -> bool:
        try:
            mtime = self.config_path.stat().st_mtime
        except OSError:
            return False
        if mtime == self.config_mtime:
            return False
        self.config_mtime = mtime
        try:
            candidate = await asyncio.to_thread(load_config, self.config_path)
        except ConfigError as exc:
            self.metrics.inc("config_reloads_total", outcome="invalid")
            log.error(
                "config reload rejected: invalid",
                extra={"keeping_policy": self.config.policy.version, "error": str(exc)},
            )
            return False
        if candidate.restart_scope() != self.config.restart_scope():
            self.metrics.inc("config_reloads_total", outcome="restart_required")
            log.error(
                "config reload rejected: ntfy/network/database/secret/endpoint changes require a restart",
                extra={"keeping_policy": self.config.policy.version},
            )
            return False
        if candidate.bridge.mode != "shadow" and not self.hermes.secret:
            error = f"mode {candidate.bridge.mode!r} requires ${candidate.hermes.secret_env} for signed Hermes delivery"
            self.metrics.inc("config_reloads_total", outcome="invalid")
            log.error(
                "config reload rejected: invalid",
                extra={"keeping_policy": self.config.policy.version, "error": error},
            )
            return False
        ctx = Context.build(candidate)
        ctx.guardrail = await self.pipeline.compute_guardrail(ctx)
        previous = self.config.bridge
        self.pipeline.ctx = ctx
        if (candidate.bridge.log_level, candidate.bridge.log_format) != (previous.log_level, previous.log_format):
            setup_logging(candidate.bridge.log_level, candidate.bridge.log_format)
        self.metrics.inc("config_reloads_total", outcome="applied")
        log.info(
            "config reloaded",
            extra={
                "mode": candidate.bridge.mode,
                "policy_version": candidate.policy.version,
                "policy_hash": ctx.policy_hash,
            },
        )
        return True


def run(config_path: Path) -> int:
    config = load_config(config_path)
    setup_logging(config.bridge.log_level, config.bridge.log_format)

    async def main() -> None:
        app = App(config, config_path=config_path)
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, task.cancel)
        try:
            await app.run()
        except asyncio.CancelledError:
            log.info("shutting down")
        finally:
            await app.close()

    asyncio.run(main())
    return 0
