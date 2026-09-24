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

from .config import Config, ConfigError, TopicSettings, load_config, secret, tls_context
from .digest import run_due_digest
from .hermes import HermesClient, fallback_ntfy_payload, publish_ntfy
from .jev import JevClient
from .metrics import Metrics
from .models import INTERNAL_EVENT_PREFIX, iso_from_unix, now_iso
from .normalize import MESSAGE_ID_RE
from .pipeline import Context, Pipeline
from .store import OutboxInsert, Store

log = logging.getLogger(__name__)

GUARDRAIL_REFRESH_SECONDS = 600
RELOAD_POLL_SECONDS = 5
PRUNE_INTERVAL_SECONDS = 86_400


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
            log.info("resuming %d events interrupted mid-processing", reset)
        await self.refresh_guardrail()
        log.info(
            "bridge starting: mode=%s policy=%s (%s) jev=%s topics=%s",
            self.config.bridge.mode,
            self.config.policy.version,
            self.ctx.policy_hash,
            self.config.typesafe.model if self.config.typesafe.enabled else "disabled (local-only)",
            ",".join(self.connected),
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
                log.warning("ntfy %s stream error: %s", topic.name, exc)
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
            if response.headers.get("x-messages-truncated") == "1":
                self.metrics.inc("ntfy_truncated_replays_total", topic=topic.name)
                log.error("ntfy %s replay was truncated by the server; older cached messages were lost", topic.name)
            self._set_connected(topic.name, True)
            log.info("ntfy %s connected (since=%s)", topic.name, params.get("since", "now"))
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
        valid_time = isinstance(stamp, (int, float)) and not isinstance(stamp, bool)
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
            log.exception("processing %s failed (event now %s)", row["event_id"], status)
            return
        if decision is not None:
            log.info(
                "decided %s source=%s proposed=%s effective=%s rule=%s",
                decision.event.event_id,
                decision.event.source,
                decision.proposed,
                decision.effective,
                decision.rule or "-",
            )
            if decision.effective in ("NOTIFY_NOW", "REVIEW"):
                self.outbox_wake.set()

    async def refresh_guardrail(self) -> None:
        ctx = self.ctx
        ctx.guardrail = await self.pipeline.compute_guardrail(ctx)
        if ctx.config.bridge.mode == "full":
            log.info("DROP guardrail %s", ctx.guardrail.describe())

    # ---- delivery ---------------------------------------------------------------------------

    async def outbox_loop(self) -> None:
        while True:
            self.outbox_wake.clear()
            rows = self.store.due_outbox(now_iso(), self.config.outbox.concurrency)
            if rows:
                await asyncio.gather(*(self.deliver(row) for row in rows))
                continue
            due = self.store.next_outbox_due()
            wait = 5.0  # also picks up work enqueued by the CLI (digest flush, outbox retry)
            if due:
                wait = max(0.05, min(wait, (datetime.fromisoformat(due) - datetime.now(UTC)).total_seconds()))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.outbox_wake.wait(), timeout=wait)

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
            log.info("delivered outbox #%d %s %s", row["id"], kind, row["request_id"])
            return
        if not outcome.retryable or attempts >= config.outbox.max_attempts:
            self.store.outbox_dead(row, error=outcome.detail)
            self.metrics.inc("deliveries_total", kind=kind, outcome="dead")
            log.error("outbox #%d %s dead-lettered after %d attempts: %s", row["id"], kind, attempts, outcome.detail)
        else:
            delay = min(config.outbox.max_backoff_seconds, config.outbox.base_backoff_seconds * 2 ** (attempts - 1))
            due = (datetime.now(UTC) + timedelta(seconds=delay * random.uniform(0.8, 1.2))).isoformat(
                timespec="microseconds"
            )
            self.store.outbox_retry(row["id"], error=outcome.detail, next_attempt_at=due)
            self.metrics.inc("deliveries_total", kind=kind, outcome="retry")
            log.warning("outbox #%d %s attempt %d failed: %s", row["id"], kind, attempts, outcome.detail)
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
            log.warning("Hermes unavailable for critical %s; queued clean-ntfy fallback", row["request_id"])
            self.outbox_wake.set()

    # ---- digests ----------------------------------------------------------------------------

    async def digest_loop(self) -> None:
        while True:
            parts = run_due_digest(self.store, self.config, datetime.now(UTC))
            if parts:
                self.metrics.inc("digests_total", parts)
                log.info("enqueued digest in %d part(s)", parts)
                self.outbox_wake.set()
            await asyncio.sleep(30)

    # ---- health -----------------------------------------------------------------------------

    def health(self) -> dict:
        counts = self.store.counts()
        now = time.monotonic()
        outage = self.config.health.ingest_outage_seconds
        ingest_down = [t for t, up in self.connected.items() if not up and now - self.disconnected_since[t] > outage]
        delivery_down = counts["outbox_oldest_pending_seconds"] > self.config.health.delivery_outage_seconds
        status = "ok" if not ingest_down and not delivery_down and not counts["outbox_dead"] else "degraded"
        return {
            "status": status,
            "mode": self.config.bridge.mode,
            "policy_version": self.config.policy.version,
            "policy_hash": self.ctx.policy_hash,
            "jev_model": self.config.typesafe.model if self.config.typesafe.enabled else None,
            "drop_guardrail": self.ctx.guardrail.describe(),
            "topics": {t: ("connected" if up else "disconnected") for t, up in self.connected.items()},
            "ingest_outage_topics": ingest_down,
            "delivery_outage": delivery_down,
            **counts,
        }

    async def health_loop(self) -> None:
        while True:
            await asyncio.sleep(15)
            snapshot = self.health()
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

    def check_alert(self, kind: str, active: bool, message: str) -> None:
        """Raise one bridge-health event per outage; re-arm once the condition clears."""
        if not active:
            self.alerts_active.discard(kind)
            return
        if kind in self.alerts_active:
            return
        self.alerts_active.add(kind)
        self.metrics.inc("health_alerts_total", kind=kind)
        self.raise_internal_event(kind, message)

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
        log.error("bridge health alert: %s", message)
        self.wake.set()

    async def serve_http(self) -> None:
        host, port = self.config.health.listen.rsplit(":", 1)

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                request_line = await asyncio.wait_for(reader.readline(), timeout=5)
                while (await asyncio.wait_for(reader.readline(), timeout=5)).strip():
                    pass
                parts = request_line.decode("latin-1").split()
                path = parts[1] if len(parts) >= 2 else "/"
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
                writer.write(
                    f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
            except (TimeoutError, ConnectionError):
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handle, host, int(port))
        log.info("health/metrics listening on http://%s:%s", host, port)
        async with server:
            await server.serve_forever()

    # ---- maintenance / reload ---------------------------------------------------------------

    async def maintenance_loop(self) -> None:
        last_prune = 0.0
        while True:
            await asyncio.sleep(GUARDRAIL_REFRESH_SECONDS)
            await self.refresh_guardrail()
            if time.monotonic() - last_prune > PRUNE_INTERVAL_SECONDS:
                pruned = self.store.prune(self.config.retention.days)
                last_prune = time.monotonic()
                if pruned:
                    log.info("pruned %d events past %d-day retention", pruned, self.config.retention.days)

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
            log.error("config reload rejected; keeping policy %s: %s", self.config.policy.version, exc)
            return False
        if candidate.restart_scope() != self.config.restart_scope():
            self.metrics.inc("config_reloads_total", outcome="restart_required")
            log.error("config reload rejected: ntfy/network/database/secret/endpoint changes require a restart")
            return False
        ctx = Context.build(candidate)
        ctx.guardrail = await self.pipeline.compute_guardrail(ctx)
        self.pipeline.ctx = ctx
        self.metrics.inc("config_reloads_total", outcome="applied")
        log.info(
            "config reloaded: mode=%s policy=%s (%s)", candidate.bridge.mode, candidate.policy.version, ctx.policy_hash
        )
        return True


def run(config_path: Path) -> int:
    config = load_config(config_path)
    logging.basicConfig(level=config.bridge.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # httpx logs full request URLs at INFO; keep them out of the bridge log.
    logging.getLogger("httpx").setLevel(logging.WARNING)

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
