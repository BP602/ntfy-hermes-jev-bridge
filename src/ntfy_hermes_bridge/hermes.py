"""Signed Hermes webhook delivery and the optional clean-ntfy fallback."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass

import httpx

from .models import PRIORITY_LABELS, CanonicalEvent

# Statuses that will not succeed on retry without a configuration change or a smaller body.
PERMANENT_STATUSES = frozenset({400, 404, 405, 413, 422})


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    ok: bool
    retryable: bool
    detail: str


def sign_v2(secret: bytes, timestamp: int, body: bytes) -> str:
    """Hermes Generic V2: hex HMAC-SHA256 over `<timestamp>.<body>`."""
    return hmac.new(secret, str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()


def encode(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()


def _outcome(response: httpx.Response) -> DeliveryOutcome:
    status = response.status_code
    if 200 <= status < 300:
        return DeliveryOutcome(True, False, f"HTTP {status} {response.text[:120]}")
    return DeliveryOutcome(False, status not in PERMANENT_STATUSES, f"HTTP {status} {response.text[:200]}")


class HermesClient:
    def __init__(self, http: httpx.AsyncClient, secret: str):
        self.http = http
        self.secret = secret.encode()

    async def post(
        self, base_url: str, route: str, payload: dict, *, request_id: str, timeout: float
    ) -> DeliveryOutcome:
        body = encode(payload)
        timestamp = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": str(timestamp),
            "X-Webhook-Signature-V2": sign_v2(self.secret, timestamp, body),
            "X-Request-ID": request_id,
        }
        url = f"{base_url.rstrip('/')}/webhooks/{route}"
        try:
            response = await self.http.post(url, content=body, headers=headers, timeout=timeout)
        except httpx.TransportError as exc:
            return DeliveryOutcome(False, True, f"transport error: {type(exc).__name__}")
        return _outcome(response)


async def publish_ntfy(
    http: httpx.AsyncClient, base_url: str, token: str, payload: dict, *, timeout: float
) -> DeliveryOutcome:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    try:
        response = await http.post(base_url.rstrip("/") + "/", json=payload, headers=headers, timeout=timeout)
    except httpx.TransportError as exc:
        return DeliveryOutcome(False, True, f"transport error: {type(exc).__name__}")
    return _outcome(response)


def _event_fields(event: CanonicalEvent) -> dict:
    return {
        "event_id": event.event_id,
        "ref": event.ref,
        "source": event.source,
        "entity": event.source_entity,
        "event_kind": event.event_kind,
        "priority": event.priority,
        "priority_label": PRIORITY_LABELS[event.priority],
        "tags": list(event.tags),
        "title": event.title,
        "message": event.message,
        "click_url": event.click_url,
        "occurred_at": event.occurred_at,
        "repeat_bucket": event.repeat_bucket,
        "recency_bucket": event.recency_bucket,
    }


def compose_payload(event: CanonicalEvent, *, category: str | None, reasons: list[str], rule: str | None) -> dict:
    return {
        "event_type": "notification.compose",
        **_event_fields(event),
        "category": category,
        "deterministic_rule": rule,
        "reasons": reasons,
    }


def review_payload(event: CanonicalEvent, *, jev: dict | None, reasons: list[str], proposed: str) -> dict:
    return {
        "event_type": "notification.review",
        **_event_fields(event),
        "proposed_route": proposed,
        "jev": jev,
        "reasons": reasons,
    }


def fallback_ntfy_payload(event: dict, *, topic: str, echo_tag: str) -> dict:
    """Deterministic clean-ntfy alert used when Hermes cannot accept a critical event."""
    what = event.get("title") or event.get("event_kind") or "event"
    lines = [
        f"🚨 {event['source']}: {what}",
        f"Why it matters: {', '.join(event.get('reasons') or []) or 'critical deterministic rule matched'}",
        f"Suggested next step: check {event['source']} ({event.get('entity') or 'unknown entity'})",
    ]
    if event.get("click_url"):
        lines.append(f"Open: {event['click_url']}")
    lines.append(f"Ref: {event['ref']}")
    return {
        "topic": topic,
        "title": f"{event['source']}: {what}"[:200],
        "message": "\n".join(lines),
        "priority": 5,
        "tags": ["rotating_light", echo_tag],
        **({"click": event["click_url"]} if event.get("click_url") else {}),
    }
