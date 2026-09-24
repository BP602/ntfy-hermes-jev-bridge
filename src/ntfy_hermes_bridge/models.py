from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum


class Route(StrEnum):
    NOTIFY_NOW = "NOTIFY_NOW"
    REVIEW = "REVIEW"
    DIGEST = "DIGEST"
    DROP = "DROP"


# Effective route when a decision is recorded but no action is taken (shadow mode, synthetic corpus).
SHADOW = "SHADOW"

PRIORITY_LABELS = {1: "min", 2: "low", 3: "default", 4: "high", 5: "urgent"}

INTERNAL_EVENT_PREFIX = "bridge:"


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def iso_from_unix(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat(timespec="microseconds")


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass(frozen=True, slots=True)
class CanonicalEvent:
    """Normalized, redacted, bounded event. Raw payloads stay in the store only."""

    event_id: str
    source: str
    source_entity: str
    event_kind: str
    occurred_at: str
    received_at: str
    topic: str
    priority: int
    tags: tuple[str, ...]
    title: str
    message: str
    click_url: str
    raw_sha256: str
    normalizer: str
    fingerprint: str = ""
    repeat_bucket: str = "first"
    recency_bucket: str = "fresh"
    schema_version: int = 1

    @property
    def ref(self) -> str:
        return self.event_id.rsplit(":", 1)[-1]

    @property
    def internal(self) -> bool:
        return self.event_id.startswith(INTERNAL_EVENT_PREFIX)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["tags"] = list(self.tags)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> CanonicalEvent:
        return cls(**{**data, "tags": tuple(data["tags"])})
