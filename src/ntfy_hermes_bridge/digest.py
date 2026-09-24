"""Scheduled digests (FR-14) with duplicate collapsing and failure/recovery correlation (FR-17)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from zoneinfo import ZoneInfo

from .config import Config
from .hermes import encode
from .redact import truncate
from .store import OutboxInsert, Store

META_LAST_SLOT = "digest_last_slot"
META_LAST_WINDOW_END = "digest_last_window_end"

# Categories that describe a problem a later `recovery` can resolve.
FAILURE_CATEGORIES = frozenset({"availability", "capacity", "data_integrity", "security", "other"})
CATEGORY_RANK = {
    c: i
    for i, c in enumerate(
        (
            "security",
            "data_integrity",
            "availability",
            "capacity",
            "actionable_change",
            "maintenance",
            "recovery",
            "informational",
            "routine_success",
            "other",
            "uncategorized",
        )
    )
}


@dataclass(slots=True)
class Entry:
    fingerprint: str
    source: str
    entity: str
    category: str
    title: str
    excerpt: str
    event_kind: str
    click_url: str
    action_useful: float
    first_seen: str
    last_seen: str
    reviewed: bool
    refs: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)

    def payload(self) -> dict:
        return {
            "refs": self.refs[:5],
            "count": len(self.event_ids),
            "entity": self.entity,
            "event_kind": self.event_kind,
            "title": self.title,
            "excerpt": self.excerpt,
            "click_url": self.click_url,
            "action_useful": round(self.action_useful, 2),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "reviewed_by_hermes": self.reviewed,
        }


def last_slot(now: datetime, schedule: tuple[str, ...], tz: ZoneInfo) -> datetime | None:
    """Most recent scheduled slot at or before `now`, as an aware datetime."""
    if not schedule:
        return None
    local = now.astimezone(tz)
    candidates = []
    for day_offset in (0, -1):
        day = (local + timedelta(days=day_offset)).date()
        for slot in schedule:
            hh, mm = map(int, slot.split(":"))
            candidate = datetime.combine(day, time(hh, mm), tz)
            if candidate <= local:
                candidates.append(candidate)
    return max(candidates) if candidates else None


def _entries(rows, excerpt_chars: int) -> list[Entry]:
    by_fp: dict[str, Entry] = {}
    for row in rows:
        event = json.loads(row["canonical_json"])
        answers = json.loads(row["jev_answers_json"]) if row["jev_answers_json"] else None
        category = answers["category"]["choice"] if answers else "uncategorized"
        action = answers["human_action_useful"] if answers else 0.5
        entry = by_fp.get(event["fingerprint"])
        if entry is None:
            entry = by_fp[event["fingerprint"]] = Entry(
                fingerprint=event["fingerprint"],
                source=event["source"],
                entity=event["source_entity"],
                category=category,
                title=event["title"],
                excerpt=truncate(event["message"], excerpt_chars),
                event_kind=event["event_kind"],
                click_url=event["click_url"],
                action_useful=action,
                first_seen=event["received_at"],
                last_seen=event["received_at"],
                reviewed=row["route"] == "REVIEW",
            )
        entry.refs.append(event["event_id"].rsplit(":", 1)[-1])
        entry.event_ids.append(event["event_id"])
        entry.last_seen = max(entry.last_seen, event["received_at"])
        entry.action_useful = max(entry.action_useful, action)
        entry.reviewed = entry.reviewed or row["route"] == "REVIEW"
    return list(by_fp.values())


def _resolved_transients(entries: list[Entry]) -> tuple[list[Entry], list[dict], list[list[str]]]:
    """Collapse failures whose entity later reported a recovery into compact resolved records."""
    by_entity: dict[tuple[str, str], list[Entry]] = {}
    for entry in entries:
        by_entity.setdefault((entry.source, entry.entity), []).append(entry)
    remaining: list[Entry] = []
    resolved: list[dict] = []
    resolved_ids: list[list[str]] = []
    for (source, entity), group in by_entity.items():
        group.sort(key=lambda e: e.last_seen)
        last = group[-1]
        failures = [e for e in group[:-1] if e.category in FAILURE_CATEGORIES]
        if last.category == "recovery" and failures:
            resolved.append(
                {
                    "source": source,
                    "entity": entity,
                    "failure_titles": [f.title for f in failures][:3],
                    "failures": sum(len(f.event_ids) for f in failures),
                    "first_failure": min(f.first_seen for f in failures),
                    "recovered_at": last.last_seen,
                    "recovery_title": last.title,
                    "refs": [r for f in (*failures, last) for r in f.refs][:5],
                }
            )
            resolved_ids.append([i for f in (*failures, last) for i in f.event_ids])
            remaining.extend(e for e in group[:-1] if e not in failures)
        else:
            remaining.extend(group)
    return remaining, resolved, resolved_ids


def build_parts(
    rows, config: Config, *, digest_id: str, window_start: str, window_end: str
) -> list[tuple[dict, list[str]]]:
    """Group pending items into one or more payloads that each fit Hermes' body limit."""
    entries, resolved, resolved_ids = _resolved_transients(_entries(rows, config.digest.item_excerpt_chars))
    groups: dict[tuple[str, str], list[Entry]] = {}
    for entry in entries:
        groups.setdefault((entry.category, entry.source), []).append(entry)
    ordered = sorted(
        groups.items(),
        key=lambda kv: (-max(e.action_useful for e in kv[1]), CATEGORY_RANK.get(kv[0][0], 99), kv[0][1]),
    )
    # Flatten to (group key, item payload, event ids) units so large groups can span parts.
    units: list[tuple[tuple[str, str], dict, list[str]]] = []
    for key, items in ordered:
        items.sort(key=lambda e: (-e.action_useful, e.last_seen))
        units += [(key, e.payload(), e.event_ids) for e in items]
    units += [(("resolved_transients", r["source"]), r, ids) for r, ids in zip(resolved, resolved_ids, strict=True)]

    budget = int(config.hermes.max_body_bytes * 0.8)
    parts: list[tuple[list, list[str]]] = []
    current: list = []
    current_ids: list[str] = []
    size = 0
    for key, item, ids in units:
        item_size = len(encode(item)) + 64
        if current and (len(current) >= config.digest.max_items_per_part or size + item_size > budget):
            parts.append((current, current_ids))
            current, current_ids, size = [], [], 0
        current.append((key, item))
        current_ids.extend(ids)
        size += item_size
    if current:
        parts.append((current, current_ids))

    payloads = []
    for index, (units_in_part, ids) in enumerate(parts, start=1):
        grouped: dict[tuple[str, str], list[dict]] = {}
        for key, item in units_in_part:
            grouped.setdefault(key, []).append(item)
        payloads.append(
            (
                {
                    "event_type": "notification.digest",
                    "digest_id": digest_id,
                    "part": index,
                    "parts": len(parts),
                    "window_start": window_start,
                    "window_end": window_end,
                    "event_count": len(ids),
                    "groups": [{"category": c, "source": s, "items": items} for (c, s), items in grouped.items()],
                },
                ids,
            )
        )
    return payloads


def enqueue_digest(store: Store, config: Config, *, digest_id: str, window_start: str, window_end: str) -> int:
    """Turn every pending digest item into signed-outbox parts. Returns the number of parts."""
    rows = store.pending_digest_items()
    if not rows:
        return 0
    parts = build_parts(rows, config, digest_id=digest_id, window_start=window_start, window_end=window_end)
    store.commit_digest(
        [
            (
                OutboxInsert(
                    "digest", request_id=f"{digest_id}#p{p['part']}", payload=p, digest_id=f"{digest_id}#p{p['part']}"
                ),
                ids,
            )
            for p, ids in parts
        ]
    )
    return len(parts)


def run_due_digest(store: Store, config: Config, now: datetime, *, force: bool = False) -> int:
    """Enqueue a digest if a scheduled slot has passed since the last one (or immediately when forced)."""
    tz = ZoneInfo(config.bridge.timezone)
    slot = now if force else last_slot(now, config.digest.schedule, tz)
    if slot is None:
        return 0
    slot_iso = slot.isoformat()
    last = store.get_meta(META_LAST_SLOT)
    if not force and last is None:
        store.set_meta(META_LAST_SLOT, slot_iso)  # first start: begin from the current slot
        return 0
    if not force and datetime.fromisoformat(last) >= slot:
        return 0
    window_start = store.get_meta(META_LAST_WINDOW_END) or (last or slot_iso)
    digest_id = "digest-" + slot.astimezone(tz).strftime("%Y%m%dT%H%M%S")
    parts = enqueue_digest(store, config, digest_id=digest_id, window_start=window_start, window_end=slot_iso)
    if not force:
        store.set_meta(META_LAST_SLOT, slot_iso)
    store.set_meta(META_LAST_WINDOW_END, slot_iso)
    return parts
