"""Map ntfy messages to canonical events. All text is redacted and bounded here."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import TopicSettings
from .models import CanonicalEvent, iso_from_unix
from .redact import URL_RE, Redactor, sanitize_url, truncate

MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_TAGS = 10
TAG_CHARS = 40
ENTITY_CHARS = 200
URL_CHARS = 500


class MalformedMessage(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Fields:
    source: str
    source_entity: str
    event_kind: str
    title: str
    message: str
    click_url: str


def _generic(msg: dict, topic: TopicSettings) -> Fields:
    title = msg.get("title") or ""
    message = msg.get("message") or ""
    first_line = message.strip().splitlines()[0] if message.strip() else ""
    return Fields(
        source=topic.source or topic.name,
        source_entity=title or first_line[:120] or topic.name,
        event_kind="notification",
        title=title,
        message=message,
        click_url=msg.get("click") or "",
    )


CD_TITLE_PREFIX = re.compile(r"^\s*changedetection(?:\.io)?(?:\s+notification)?\s*[-:–]\s*", re.IGNORECASE)
# Notification body template of the form `key: value` lines, where `change:` runs to the end of the body.
CD_FIELD = re.compile(r"^(source|watch|watch_url|diff_url|triggered_text|change):[ \t]*(.*)$")
CD_DIFF_PATH = re.compile(r"/(?:diff|preview)/", re.IGNORECASE)
CD_KINDS = (
    (
        "watch_error",
        re.compile(r"\b(filter not found|fetch(ing)? (error|failed)|error text|non-2\d\d|timed? ?out)\b", re.I),
    ),
    ("restock_changed", re.compile(r"\b(restock|back in stock|in stock|out of stock|availability)\b", re.I)),
    ("price_changed", re.compile(r"\b(price|\$\s?\d|€\s?\d|£\s?\d)", re.I)),
)


def _entity_from_url(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path.rstrip("/")
    return f"{parts.hostname or ''}{path}" or url


def _cd_fields(message: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    lines = message.splitlines()
    for index, line in enumerate(lines):
        match = CD_FIELD.match(line)
        if not match:
            continue
        key, value = match.groups()
        if key == "change":
            fields[key] = "\n".join([value, *lines[index + 1 :]])
            break
        fields[key] = value.strip()
    return fields


def _compact(text: str) -> str:
    """Collapse the column padding ChangeDetection leaves in diff text."""
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def _http_url(value: str) -> str:
    return value if URL_RE.fullmatch(value or "") else ""


def _changedetection(msg: dict, topic: TopicSettings) -> Fields:
    title = msg.get("title") or ""
    message = msg.get("message") or ""
    fields = _cd_fields(message)
    if "change" in fields:
        # diff_url is not a URL when ChangeDetection's "Base URL" setting is empty.
        diff_url = _http_url(fields.get("diff_url", ""))
        watch_url = _http_url(fields.get("watch_url", ""))
        triggered = _compact(fields.get("triggered_text", ""))
        body = _compact(fields["change"])
        message = f"triggered: {triggered}\n{body}" if triggered else body
        named_entity = fields.get("watch", "")
        kind_text = " ".join([triggered, body, *msg.get("tags", [])])
    else:
        urls = URL_RE.findall(f"{title}\n{message}")
        diff_url = next((u for u in urls if CD_DIFF_PATH.search(u)), "")
        watch_url = next((u for u in urls if not CD_DIFF_PATH.search(u)), "")
        named_entity = CD_TITLE_PREFIX.sub("", title).strip()
        kind_text = " ".join([title, message, *msg.get("tags", [])])
    if named_entity and not URL_RE.fullmatch(named_entity):
        entity = named_entity
    elif watch_url:
        entity = _entity_from_url(watch_url)
    else:
        entity = message.strip().splitlines()[0][:120] if message.strip() else topic.name
    kind = next((name for name, pattern in CD_KINDS if pattern.search(kind_text)), "page_changed")
    return Fields(
        source=topic.source or "changedetection",
        source_entity=entity,
        event_kind=kind,
        title=title,
        message=message,
        click_url=msg.get("click") or diff_url or watch_url,
    )


def _looks_like_changedetection(msg: dict) -> bool:
    title = msg.get("title") or ""
    message = msg.get("message") or ""
    tags = [t.lower() for t in msg.get("tags") or [] if isinstance(t, str)]
    return (
        bool(CD_TITLE_PREFIX.match(title)) or message.startswith("source: changedetection") or "changedetection" in tags
    )


NORMALIZERS: dict[str, tuple[str, Callable[[dict, TopicSettings], Fields]]] = {
    "generic": ("generic-v1", _generic),
    "changedetection": ("changedetection-v2", _changedetection),
}


def validate_message(msg: object) -> dict:
    if not isinstance(msg, dict):
        raise MalformedMessage("message is not a JSON object")
    mid = msg.get("id")
    if not isinstance(mid, str) or not MESSAGE_ID_RE.match(mid):
        raise MalformedMessage("missing or invalid message id")
    if "time" in msg and not isinstance(msg["time"], (int, float)):
        raise MalformedMessage("invalid message time")
    for key in ("title", "message", "click"):
        if key in msg and msg[key] is not None and not isinstance(msg[key], str):
            raise MalformedMessage(f"field {key!r} must be a string")
    if "tags" in msg and not (isinstance(msg["tags"], list) and all(isinstance(t, str) for t in msg["tags"])):
        raise MalformedMessage("tags must be a list of strings")
    return msg


def normalize(
    msg: dict,
    *,
    event_id: str,
    topic: TopicSettings,
    received_at: str,
    raw_sha256: str,
    redactor: Redactor,
    title_chars: int,
    message_chars: int,
    counts: Counter | None = None,
) -> CanonicalEvent:
    msg = validate_message(msg)
    name = topic.normalizer
    if name == "auto":
        name = "changedetection" if _looks_like_changedetection(msg) else "generic"
    normalizer, fn = NORMALIZERS[name]
    fields = fn(msg, topic)
    priority = msg.get("priority")
    priority = priority if isinstance(priority, int) and 1 <= priority <= 5 else 3
    counts = counts if counts is not None else Counter()
    red = lambda text, limit: truncate(redactor.redact(text.strip(), counts), limit)  # noqa: E731
    tags = tuple(dict.fromkeys(red(t, TAG_CHARS) for t in (msg.get("tags") or [])[:MAX_TAGS] if t.strip()))
    click = sanitize_url(fields.click_url, counts) if fields.click_url else ""
    return CanonicalEvent(
        event_id=event_id,
        source=truncate(fields.source, 64),
        source_entity=red(fields.source_entity, ENTITY_CHARS),
        event_kind=fields.event_kind,
        occurred_at=iso_from_unix(msg["time"]) if "time" in msg else received_at,
        received_at=received_at,
        topic=topic.name,
        priority=priority,
        tags=tags,
        title=red(fields.title, title_chars),
        message=red(fields.message, message_chars),
        click_url=truncate(click, URL_CHARS) if urlsplit(click).scheme in ("http", "https") else "",
        raw_sha256=raw_sha256,
        normalizer=normalizer,
    )


def fingerprint(event: CanonicalEvent, fields: tuple[str, ...]) -> str:
    """Exact semantic fingerprint over configured canonical fields (case/whitespace-insensitive)."""
    values = [" ".join(str(getattr(event, f)).lower().split()) for f in fields]
    return hashlib.sha256(json.dumps(values, ensure_ascii=False).encode()).hexdigest()
