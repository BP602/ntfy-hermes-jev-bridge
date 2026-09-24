"""Inbox event -> canonical event -> deterministic/Jev decision -> durable next state."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import timedelta
from itertools import pairwise

from . import BUILD
from .config import Config, Thresholds, TopicSettings
from .hermes import compose_payload, review_payload
from .jev import JevAnswers, JevClient, JevError, JevResult, build_state
from .metrics import Metrics
from .models import SHADOW, CanonicalEvent, Route, now_iso, parse_iso
from .normalize import fingerprint, normalize
from .policy import DeterministicPolicy, fallback_route, gate, route_from_answers
from .questions import QUESTION_SET_VERSION
from .redact import Redactor
from .store import QUEUED, QUEUED_DIGEST, OutboxInsert, Store

log = logging.getLogger(__name__)

INTERNAL_TOPIC = TopicSettings.model_construct(name="_bridge", source="bridge", normalizer="generic")


@dataclass(frozen=True, slots=True)
class Guardrail:
    labels: int = 0
    critical: int = 0
    critical_dropped: tuple[str, ...] = ()
    min_labels: int = 0
    min_critical: int = 0
    computed: bool = False  # the default instance (before the first corpus replay) never permits DROP

    @property
    def ok(self) -> bool:
        return (
            self.computed
            and self.labels >= self.min_labels
            and self.critical >= self.min_critical
            and not self.critical_dropped
        )

    def describe(self) -> str:
        if not self.computed:
            return "FAIL: not evaluated yet"
        state = "PASS" if self.ok else "FAIL"
        text = f"{state}: {self.labels}/{self.min_labels} labeled events, {self.critical}/{self.min_critical} critical"
        if self.critical_dropped:
            text += f", critical events routed DROP: {', '.join(self.critical_dropped)}"
        return text


@dataclass(slots=True)
class Context:
    """Everything derived from one validated config; swapped atomically on hot reload."""

    config: Config
    policy_hash: str
    deterministic: DeterministicPolicy
    redactor: Redactor
    topics: dict[str, TopicSettings]
    guardrail: Guardrail = field(default_factory=Guardrail)

    @classmethod
    def build(cls, config: Config) -> Context:
        return cls(
            config=config,
            policy_hash=config.policy_hash(),
            deterministic=DeterministicPolicy(config),
            redactor=Redactor(config.policy.redaction),
            topics={t.name: t for t in config.ntfy.topics},
        )


@dataclass(slots=True)
class Decision:
    event: CanonicalEvent
    proposed: Route
    effective: str
    rule: str | None
    reasons: list[str]
    thresholds: Thresholds
    mode: str
    jev_state: dict | None = None
    jev: JevResult | None = None
    jev_error: str | None = None


def _shift(iso: str, seconds: int) -> str:
    return (parse_iso(iso) - timedelta(seconds=seconds)).isoformat(timespec="microseconds")


def _oscillations(sequence: list[str]) -> int:
    """Transitions back to an earlier state (A→B→A). Content that keeps changing (A→B→C) is not flapping."""
    seen: set[str] = set()
    returns = 0
    for previous, current in pairwise(sequence):
        seen.add(previous)
        if current != previous and current in seen:
            returns += 1
    return returns


class Pipeline:
    def __init__(self, store: Store, metrics: Metrics, jev: JevClient | None, ctx: Context):
        self.store = store
        self.metrics = metrics
        self.jev = jev
        self.ctx = ctx

    # ---- normalization ----------------------------------------------------------------------

    def canonical(self, row: sqlite3.Row, ctx: Context) -> CanonicalEvent:
        """Rebuild the canonical event from the stored raw message, with history as of its arrival."""
        policy = ctx.config.policy
        topic = (
            INTERNAL_TOPIC
            if row["topic"] == "_bridge"
            else ctx.topics.get(row["topic"]) or TopicSettings(name=row["topic"])
        )
        counts: Counter = Counter()
        event = normalize(
            json.loads(row["raw_json"]),
            event_id=row["event_id"],
            topic=topic,
            received_at=row["received_at"],
            raw_sha256=row["raw_sha256"],
            redactor=ctx.redactor,
            title_chars=policy.title_chars,
            message_chars=ctx.config.typesafe.excerpt_chars,
            counts=counts,
        )
        for kind, n in counts.items():
            self.metrics.inc("redactions_total", n, kind=kind)
        event = replace(event, fingerprint=fingerprint(event, policy.fingerprint_fields))
        return replace(
            event, repeat_bucket=self._repeat_bucket(event, policy), recency_bucket=self._recency(event, policy)
        )

    def _repeat_bucket(self, event: CanonicalEvent, policy) -> str:
        before = event.received_at
        if policy.flap_window_seconds:
            history = self.store.entity_fingerprints(
                event.source,
                event.source_entity,
                since=_shift(before, policy.flap_window_seconds),
                before=before,
                exclude=event.event_id,
            )
            sequence = [*history, event.fingerprint]
            if _oscillations(sequence) >= policy.flap_min_transitions - 1:
                return "flapping"
        if policy.dedupe_window_seconds and self.store.fingerprint_seen(
            event.fingerprint, since=_shift(before, policy.dedupe_window_seconds), before=before, exclude=event.event_id
        ):
            return "repeated"
        return "first"

    @staticmethod
    def _recency(event: CanonicalEvent, policy) -> str:
        lag = (parse_iso(event.received_at) - parse_iso(event.occurred_at)).total_seconds()
        return "stale" if lag > policy.stale_after_seconds else "fresh"

    # ---- decision ---------------------------------------------------------------------------

    async def decide(
        self,
        event: CanonicalEvent,
        ctx: Context,
        *,
        synthetic: bool,
        stored: JevResult | None = None,
        allow_classify: bool = True,
    ) -> Decision:
        config = ctx.config
        thresholds = config.thresholds_for(event.source)
        decision = Decision(event, Route.REVIEW, SHADOW, None, [], thresholds, config.bridge.mode)
        match = ctx.deterministic.evaluate(event)
        if match:
            decision.proposed, decision.rule = match.route, match.rule
            decision.reasons.append(match.reason)
        elif not config.jev_enabled_for(event.source):
            decision.proposed = fallback_route(event, config.fallback_route_for(event.source))
            decision.reasons.append("local-only: classifier disabled for this source; deterministic fallback")
        else:
            decision.jev_state = build_state(event, config.policy.user_policy)
            if stored is not None:
                decision.jev = stored
            elif allow_classify:
                decision.jev, decision.jev_error = await self._classify(decision.jev_state, ctx)
            else:
                decision.jev_error = "no stored classification (replay with --reclassify)"
            if decision.jev is not None:
                decision.proposed, why = route_from_answers(decision.jev.answers, thresholds)
                decision.reasons.extend(why)
            else:
                decision.proposed = fallback_route(event, config.fallback_route_for(event.source))
                decision.reasons.append(f"classifier unavailable ({decision.jev_error}); fallback never drops")

        if decision.proposed in (Route.NOTIFY_NOW, Route.REVIEW) and decision.rule != "bridge_health":
            self._apply_cooldown(decision, config)

        decision.effective, why = gate(
            decision.proposed,
            mode=config.bridge.mode,
            deterministic=decision.rule is not None,
            drop_allowed=ctx.guardrail.ok,
            synthetic=synthetic,
        )
        decision.reasons.extend(why)
        return decision

    async def _classify(self, state: dict, ctx: Context) -> tuple[JevResult | None, str | None]:
        if self.jev is None:
            return None, "classifier client not configured"
        leaks = ctx.redactor.leaks(state)
        if leaks:
            self.metrics.inc("jev_state_blocked_total")
            return None, f"outbound state blocked by redaction guard ({', '.join(sorted(set(leaks)))})"
        try:
            result = await self.jev.classify(state, ctx.config.typesafe)
        except JevError as exc:
            self.metrics.inc("jev_requests_total", outcome="retryable_error" if exc.retryable else "error")
            log.warning("jev classification failed", extra={"error": str(exc), "retryable": exc.retryable})
            return None, str(exc)
        self.metrics.inc("jev_requests_total", outcome="ok")
        self.metrics.inc("jev_input_tokens_total", result.input_tokens)
        self.metrics.inc("jev_output_tokens_total", result.output_tokens)
        self.metrics.inc("jev_estimated_cost_usd_total", self._cost(result, ctx.config))
        self.metrics.observe_latency(result.latency_ms)
        return result, None

    @staticmethod
    def _cost(result: JevResult, config: Config) -> float:
        return result.input_tokens * config.typesafe.price_per_million_input_tokens / 1_000_000

    def _apply_cooldown(self, decision: Decision, config: Config) -> None:
        seconds = config.policy.cooldown_seconds
        if not seconds:
            return
        event = decision.event
        prior = self.store.recent_hermes_event(
            event.fingerprint,
            since=_shift(event.received_at, seconds),
            before=event.received_at,
            exclude=event.event_id,
        )
        if prior is not None:
            decision.reasons.append(
                f"cooldown: identical event {prior['event_id']} sent as {prior['route']} at {prior['received_at']}; "
                f"{decision.proposed} downgraded to DIGEST"
            )
            decision.proposed = Route.DIGEST

    # ---- persistence ------------------------------------------------------------------------

    def record(self, decision: Decision, ctx: Context) -> dict:
        jev = decision.jev
        return {
            "created_at": now_iso(),
            "mode": decision.mode,
            "bridge_version": BUILD,
            "policy_version": ctx.config.policy.version,
            "policy_hash": ctx.policy_hash,
            "question_set_version": QUESTION_SET_VERSION,
            "thresholds_json": decision.thresholds.model_dump_json(),
            "jev_model_requested": ctx.config.typesafe.model if decision.jev_state is not None else None,
            "jev_model": jev.model if jev else None,
            "jev_state_json": json.dumps(decision.jev_state, ensure_ascii=False) if decision.jev_state else None,
            "jev_answers_json": json.dumps(jev.answers.to_json()) if jev else None,
            "jev_error": decision.jev_error,
            "input_tokens": jev.input_tokens if jev else None,
            "output_tokens": jev.output_tokens if jev else None,
            "estimated_cost_usd": self._cost(jev, ctx.config) if jev else None,
            "jev_latency_ms": jev.latency_ms if jev else None,
            "deterministic_rule": decision.rule,
            "proposed_route": str(decision.proposed),
            "effective_route": str(decision.effective),
            "reasons_json": json.dumps(decision.reasons, ensure_ascii=False),
        }

    def commit(self, decision: Decision, ctx: Context) -> None:
        event = decision.event
        effective = decision.effective
        outbox: OutboxInsert | None = None
        digest = False
        category = decision.jev.answers.category if decision.jev else None
        if effective == SHADOW:
            status = "shadow"
        elif effective == Route.DROP:
            status = "dropped"
        elif effective == Route.DIGEST:
            status, digest = QUEUED_DIGEST, True
        elif effective == Route.NOTIFY_NOW:
            status = QUEUED
            outbox = OutboxInsert(
                "compose",
                request_id=event.event_id,
                payload=compose_payload(event, category=category, reasons=decision.reasons, rule=decision.rule),
                critical=decision.rule is not None,
            )
        else:
            # REVIEW also lands in the digest queue, so a Hermes [SILENT] verdict can never lose the event.
            status, digest = QUEUED, True
            outbox = OutboxInsert(
                "review",
                request_id=event.event_id,
                payload=review_payload(
                    event,
                    jev=_jev_summary(decision.jev),
                    reasons=decision.reasons,
                    proposed=str(decision.proposed),
                ),
            )
        self.store.commit_production_decision(
            event_id=event.event_id,
            canonical=event.to_dict(),
            record=self.record(decision, ctx),
            status=status,
            route=str(effective),
            outbox=outbox,
            digest=digest,
        )
        self.metrics.inc("decisions_total", proposed=str(decision.proposed), effective=str(effective))

    async def process(self, row: sqlite3.Row) -> Decision | None:
        ctx = self.ctx
        try:
            event = self.canonical(row, ctx)
        except ValueError as exc:  # MalformedMessage and JSON errors
            self.store.mark_quarantined(row["event_id"], f"normalization failed: {exc}")
            self.metrics.inc("events_quarantined_total")
            log.warning("event quarantined", extra={"event_id": row["event_id"], "error": str(exc)})
            return None
        decision = await self.decide(event, ctx, synthetic=bool(row["synthetic"]))
        self.commit(decision, ctx)
        return decision

    # ---- replay / evaluation ----------------------------------------------------------------

    def stored_result(self, event_id: str) -> JevResult | None:
        row = self.store.latest_decision(event_id)
        if row is None or not row["jev_answers_json"]:
            return None
        return JevResult(
            model=row["jev_model"],
            answers=JevAnswers.from_json(json.loads(row["jev_answers_json"])),
            input_tokens=row["input_tokens"] or 0,
            output_tokens=row["output_tokens"] or 0,
            latency_ms=row["jev_latency_ms"] or 0,
        )

    async def replay(self, row: sqlite3.Row, ctx: Context, *, reclassify: bool) -> Decision:
        event = self.canonical(row, ctx)
        stored = None if reclassify else self.stored_result(row["event_id"])
        decision = await self.decide(
            event, ctx, synthetic=bool(row["synthetic"]), stored=stored, allow_classify=reclassify
        )
        if stored is not None and stored.model != ctx.config.typesafe.model:
            decision.reasons.append(f"stored answers came from {stored.model}, not {ctx.config.typesafe.model}")
        return decision

    async def compute_guardrail(self, ctx: Context) -> Guardrail:
        """DROP guardrails: enough labels, enough critical labels, and no critical event proposed DROP."""
        labels = self.store.latest_labels()
        critical = [label for label in labels if label["critical"]]
        dropped = []
        for label in critical:
            row = self.store.get_event(label["event_id"])
            try:
                decision = await self.replay(row, ctx, reclassify=False)
            except ValueError:
                continue
            if decision.proposed is Route.DROP:
                dropped.append(decision.event.ref)
        return Guardrail(
            labels=len(labels),
            critical=len(critical),
            critical_dropped=tuple(dropped),
            min_labels=ctx.config.policy.min_labels_for_drop,
            min_critical=ctx.config.policy.min_critical_labels_for_drop,
            computed=True,
        )


def _jev_summary(result: JevResult | None) -> dict | None:
    if result is None:
        return None
    return {"model": result.model, **result.answers.to_json()}
