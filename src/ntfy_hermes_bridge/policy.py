"""Deterministic overrides, threshold routing, and rollout gating."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import Config, Thresholds
from .jev import JevAnswers
from .models import SHADOW, CanonicalEvent, Route

# Known critical signatures. Matching these can only escalate (never drop), so keyword matching is acceptable.
BUILTIN_SIGNATURES: tuple[tuple[str, str], ...] = (
    (
        "backup_failure",
        r"\bbackups?\b[^\n]{0,80}\b(?<!\b0 )(?<!\bno )(?<!without )"
        r"(fail(ed|ure|ing|s)?|errors?|errored|abort(ed)?|did not complete|unsuccessful)\b"
        r"|\b(?<!\b0 )(?<!\bno )(?<!without )(fail(ed|ure)?|error)\b[^\n]{0,80}\bbackups?\b",
    ),
    (
        "storage_degraded",
        r"\b(pool|zpool|raid|array|vdev|mirror)\b[^\n]{0,80}\b(degraded|faulted|unavail(able)?|offline|suspended)\b"
        r"|\b(degraded|faulted)\b[^\n]{0,40}\b(pool|zpool|raid|array|vdev)\b"
        r"|\bsmart\b[^\n]{0,40}\b(error|fail(ed|ure|ing)?)\b",
    ),
    (
        "data_corruption",
        r"\b(data corruption|corrupt(ed|ion)|checksum (errors?|mismatch)|data loss|unrecoverable (errors?|read))\b",
    ),
    (
        "intrusion",
        r"\b(intrusion|unauthori[sz]ed (access|login|ssh)|brute[- ]?force|malware|ransomware|rootkit|security breach)\b",
    ),
    (
        "power_event",
        r"\b(on battery|power (loss|failure|outage|lost)|ups\b[^\n]{0,60}\b(battery|shutdown|low|fail(ed|ure)?|overload))\b",
    ),
)

PRICE_DIFF_LINE = re.compile(r"^\((changed|into)\)\s*(.*)$", re.IGNORECASE)
PRICE_VALUE = re.compile(r"^(?:[€£$]\s*\d|(?:regular|sale|unit|price)\b)", re.IGNORECASE)
CRITICAL_REVIEW_CATEGORIES = frozenset({"security", "data_integrity"})


def _price_only_change(event: CanonicalEvent) -> bool:
    """Drop only diffs whose marked changes are exclusively price fields; additions survive."""
    if event.event_kind != "price_changed":
        return False
    changed = False
    for raw_line in event.message.splitlines():
        line = raw_line.strip()
        if not line.startswith("("):
            continue
        match = PRICE_DIFF_LINE.fullmatch(line)
        if not match or not PRICE_VALUE.match(match[2]):
            return False
        changed |= match[1].lower() == "changed"
    return changed


@dataclass(frozen=True, slots=True)
class DeterministicMatch:
    route: Route
    rule: str
    reason: str


@dataclass(frozen=True, slots=True)
class _Signature:
    name: str
    pattern: re.Pattern[str]
    sources: frozenset[str]  # empty -> every non-exempt source


class DeterministicPolicy:
    def __init__(self, config: Config):
        policy = config.policy
        self.echo_tags = frozenset(t.lower() for t in policy.echo_tags)
        self.test_tags = frozenset(t.lower() for t in policy.test_tags)
        self.drop_fingerprints = frozenset(policy.always_drop.fingerprints)
        self.price_only_sources = frozenset(
            source for source, settings in config.sources.items() if settings.ignore_price_only
        )
        notify = policy.always_notify
        self.rules = notify.rules
        self.urgent_sources = frozenset(notify.urgent_priority_sources)
        self.exempt = frozenset(notify.signature_exempt_sources)
        signatures = [
            _Signature(name, re.compile(pattern, re.IGNORECASE), frozenset())
            for name, pattern in (BUILTIN_SIGNATURES if notify.builtin_signatures else ())
        ]
        signatures += [
            _Signature(s.name, re.compile(s.pattern, re.IGNORECASE), frozenset(s.sources)) for s in notify.signatures
        ]
        self.signatures = tuple(signatures)

    def evaluate(self, event: CanonicalEvent) -> DeterministicMatch | None:
        tags = {t.lower() for t in event.tags}
        # Always Drop first: loops and user-approved exact fingerprints must never page.
        if echo := tags & self.echo_tags:
            return DeterministicMatch(Route.DROP, "echo_tag", f"bridge/Hermes echo tag {sorted(echo)[0]!r}")
        if test := tags & self.test_tags:
            return DeterministicMatch(Route.DROP, "test_event", f"explicit test tag {sorted(test)[0]!r}")
        if event.fingerprint in self.drop_fingerprints:
            return DeterministicMatch(Route.DROP, "approved_fingerprint", "exact user-approved drop fingerprint")
        if event.source in self.price_only_sources and _price_only_change(event):
            return DeterministicMatch(Route.DROP, "price_only_change", "source-opted price-only diff")

        if event.internal:
            return DeterministicMatch(Route.NOTIFY_NOW, "bridge_health", "bridge health failure")
        for rule in self.rules:
            if (
                rule.source == event.source
                and (not rule.event_kind or rule.event_kind == event.event_kind)
                and (not rule.entity or rule.entity == event.source_entity)
            ):
                target = "/".join(x for x in (rule.source, rule.event_kind, rule.entity) if x)
                return DeterministicMatch(Route.NOTIFY_NOW, "allowlist", f"always-notify allowlist {target}")
        if event.priority == 5 and event.source in self.urgent_sources:
            return DeterministicMatch(
                Route.NOTIFY_NOW, "urgent_priority", f"urgent ntfy priority from allowlisted source {event.source}"
            )
        text = f"{event.title}\n{event.message}"
        for signature in self.signatures:
            if signature.sources:
                if event.source not in signature.sources:
                    continue
            elif event.source in self.exempt:
                continue
            if signature.pattern.search(text):
                return DeterministicMatch(
                    Route.NOTIFY_NOW, f"signature:{signature.name}", f"matched {signature.name} signature"
                )
        return None


def route_from_answers(answers: JevAnswers, t: Thresholds) -> tuple[Route, list[str]]:
    """Initial routing policy. Jev supplies probabilities; this code owns the decision."""
    harm = answers.noul["immediate_harm_if_ignored"]
    noise = answers.noul["routine_noise"]
    digest = answers.noul["digest_value"]
    relevance = answers.noul["personal_relevance"]
    if harm >= t.notify_harm:
        return Route.NOTIFY_NOW, [f"immediate_harm_if_ignored {harm:.2f} >= {t.notify_harm:.2f}"]
    if answers.category in t.notify_categories and answers.category_confidence >= t.notify_category_confidence:
        return Route.NOTIFY_NOW, [
            f"category {answers.category} with confidence {answers.category_confidence:.2f} "
            f">= {t.notify_category_confidence:.2f}"
        ]
    if answers.category in CRITICAL_REVIEW_CATEGORIES:
        return Route.REVIEW, [f"uncertain critical category {answers.category}; Hermes adjudicates"]
    if (
        noise >= t.drop_routine_noise
        and harm <= t.drop_max_harm
        and digest <= t.drop_max_digest_value
        and relevance <= t.drop_max_relevance
    ):
        return Route.DROP, [
            f"routine_noise {noise:.2f} >= {t.drop_routine_noise:.2f}, harm {harm:.2f} <= {t.drop_max_harm:.2f}, "
            f"digest_value {digest:.2f} <= {t.drop_max_digest_value:.2f}, "
            f"personal_relevance {relevance:.2f} <= {t.drop_max_relevance:.2f}"
        ]
    if harm >= t.review_harm:
        return Route.REVIEW, [f"immediate_harm_if_ignored {harm:.2f} >= review threshold {t.review_harm:.2f}"]
    if digest >= t.digest_value or relevance >= t.digest_relevance:
        return Route.DIGEST, [
            f"digest_value {digest:.2f} (>= {t.digest_value:.2f}?) or personal_relevance {relevance:.2f} "
            f"(>= {t.digest_relevance:.2f}?)"
        ]
    return Route.DIGEST, ["low immediate harm without a critical category; batch in digest"]


def fallback_route(event: CanonicalEvent, setting: str) -> Route:
    """Route used when Jev is disabled or unavailable. Never DROP."""
    if setting == "review":
        return Route.REVIEW
    if setting == "digest":
        return Route.DIGEST
    return Route.REVIEW if event.priority >= 4 else Route.DIGEST


def gate(
    proposed: Route, *, mode: str, deterministic: bool, drop_allowed: bool, synthetic: bool
) -> tuple[str, list[str]]:
    """Apply rollout mode to a proposed route. Returns the effective route and any reasons it changed."""
    if synthetic:
        return SHADOW, ["synthetic corpus event: recorded only"]
    if mode == "shadow":
        return SHADOW, ["shadow mode: proposed route recorded; delivery unchanged"]
    if deterministic:
        return proposed, []
    if proposed is Route.DROP and (mode == "guarded" or not drop_allowed):
        why = "guarded mode" if mode == "guarded" else "DROP guardrail not satisfied"
        return Route.DIGEST, [f"{why}: classifier DROP downgraded to DIGEST"]
    if proposed is Route.NOTIFY_NOW and mode == "guarded":
        return Route.REVIEW, ["guarded mode: classifier NOTIFY_NOW adjudicated by Hermes review"]
    return proposed, []
