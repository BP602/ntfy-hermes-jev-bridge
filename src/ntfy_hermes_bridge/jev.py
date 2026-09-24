"""TypeSafe Jev client: bounded state + atomic typed questions -> validated typed answers."""

from __future__ import annotations

import asyncio
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from .config import TypeSafeSettings, UserPolicy
from .models import PRIORITY_LABELS, CanonicalEvent
from .questions import CATEGORIES, NOUL_QUESTIONS, QUESTIONS


class JevError(Exception):
    def __init__(self, message: str, *, retryable: bool):
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class JevAnswers:
    category: str
    category_confidence: float
    category_probabilities: dict[str, float]
    noul: dict[str, float]

    def to_json(self) -> dict:
        return {
            "category": {
                "choice": self.category,
                "confidence": self.category_confidence,
                "probabilities": self.category_probabilities,
            },
            **self.noul,
        }

    @classmethod
    def from_json(cls, data: dict) -> JevAnswers:
        category = data["category"]
        return cls(
            category=category["choice"],
            category_confidence=category["confidence"],
            category_probabilities=category["probabilities"],
            noul={key: data[key] for key in NOUL_QUESTIONS},
        )


@dataclass(frozen=True, slots=True)
class JevResult:
    model: str
    answers: JevAnswers
    input_tokens: int
    output_tokens: int
    latency_ms: int


def build_state(event: CanonicalEvent, user_policy: UserPolicy) -> dict:
    """The only data allowed to leave the local network."""
    return {
        "source": event.source,
        "event_kind": event.event_kind,
        "entity": event.source_entity,
        "priority_label": PRIORITY_LABELS[event.priority],
        "tags": list(event.tags),
        "title": event.title,
        "message_excerpt": event.message,
        "repeat_bucket": event.repeat_bucket,
        "recency_bucket": event.recency_bucket,
        "user_policy": {
            "immediate": list(user_policy.immediate),
            "digest": list(user_policy.digest),
            "noise": list(user_policy.noise),
        },
    }


def _probability(value: object, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise JevError(f"invalid response: {where} is not a number", retryable=False)
    if not 0.0 <= value <= 1.0:
        raise JevError(f"invalid response: {where}={value} outside [0, 1]", retryable=False)
    return float(value)


def parse_response(payload: object) -> tuple[str, JevAnswers, int, int]:
    """Validate a /v1/systemone response against the question set's expected types."""
    if not isinstance(payload, dict):
        raise JevError("invalid response: not an object", retryable=False)
    model = payload.get("model")
    answers = payload.get("answers")
    if not isinstance(model, str) or not model:
        raise JevError("invalid response: missing model", retryable=False)
    if not isinstance(answers, dict):
        raise JevError("invalid response: missing answers", retryable=False)
    missing = set(QUESTIONS) - set(answers)
    if missing:
        raise JevError(f"invalid response: missing answers {sorted(missing)}", retryable=False)

    category = answers["category"]
    if not isinstance(category, dict) or category.get("type") != "choice":
        raise JevError("invalid response: category is not a choice answer", retryable=False)
    choice = category.get("choice")
    if choice not in CATEGORIES:
        raise JevError(f"invalid response: unknown category {choice!r}", retryable=False)
    probabilities = category.get("probabilities")
    if not isinstance(probabilities, dict) or set(probabilities) != set(CATEGORIES):
        raise JevError("invalid response: category probabilities do not match options", retryable=False)
    probabilities = {k: _probability(v, f"category.probabilities.{k}") for k, v in probabilities.items()}
    if abs(sum(probabilities.values()) - 1.0) > 0.02:
        raise JevError("invalid response: category probabilities do not sum to 1", retryable=False)
    # Equal top probabilities are valid: the API may break a tie by returning either option.
    if probabilities[choice] < max(probabilities.values()):
        raise JevError("invalid response: category choice does not have highest probability", retryable=False)
    confidence = _probability(category.get("confidence"), "category.confidence")

    noul = {}
    for key in NOUL_QUESTIONS:
        answer = answers[key]
        if not isinstance(answer, dict) or answer.get("type") != "noul":
            raise JevError(f"invalid response: {key} is not a noul answer", retryable=False)
        noul[key] = _probability(answer.get("noul"), f"{key}.noul")

    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    input_tokens = usage.get("input_tokens") if isinstance(usage.get("input_tokens"), int) else 0
    output_tokens = usage.get("output_tokens") if isinstance(usage.get("output_tokens"), int) else 0
    return model, JevAnswers(choice, confidence, probabilities, noul), input_tokens, output_tokens


def _retry_after(response: httpx.Response) -> float | None:
    try:
        return float(response.headers["retry-after"])
    except (KeyError, ValueError):
        return None


class JevClient:
    def __init__(
        self,
        http: httpx.AsyncClient,
        api_key: str,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.http = http
        self.api_key = api_key
        self.sleep = sleep

    async def classify(self, state: dict, settings: TypeSafeSettings) -> JevResult:
        body = {"state": state, "model": settings.model, "questions": QUESTIONS}
        url = settings.base_url.rstrip("/") + "/v1/systemone"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        for attempt in range(settings.max_retries + 1):
            started = time.monotonic()
            delay: float | None = None
            try:
                response = await self.http.post(url, json=body, headers=headers, timeout=settings.timeout_seconds)
            except httpx.TransportError as exc:
                error = JevError(f"transport error: {type(exc).__name__}", retryable=True)
            else:
                if response.status_code == 200:
                    try:
                        payload = response.json()
                    except ValueError:
                        raise JevError("invalid response: body is not JSON", retryable=False) from None
                    model, answers, input_tokens, output_tokens = parse_response(payload)
                    if model != settings.model and not settings.allow_model_alias:
                        raise JevError(
                            f"invalid response: model {model!r} does not match requested model {settings.model!r}",
                            retryable=False,
                        )
                    latency = int((time.monotonic() - started) * 1000)
                    return JevResult(model, answers, input_tokens, output_tokens, latency)
                status = response.status_code
                retryable = status in (429, 529) or 500 <= status < 600
                error = JevError(f"HTTP {status}: {response.text[:200]}", retryable=retryable)
                delay = _retry_after(response)
            if not error.retryable or attempt == settings.max_retries:
                raise error
            await self.sleep(min(delay if delay is not None else settings.backoff_base_seconds * 2**attempt, 10.0))
        raise AssertionError("unreachable")
