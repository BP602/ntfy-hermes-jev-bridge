from __future__ import annotations

import json
import time
from collections.abc import Callable

import httpx
import pytest

from ntfy_hermes_bridge.config import Config
from ntfy_hermes_bridge.questions import CATEGORIES

NTFY = "http://127.0.0.1:2586"
HERMES = "http://127.0.0.1:8644"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def make_config(tmp_path) -> Callable[..., Config]:
    def build(**overrides) -> Config:
        data = {
            "bridge": {"mode": "shadow", "database": str(tmp_path / "bridge.db")},
            "ntfy": {"base_url": NTFY, "topics": [{"name": "alerts", "source": "homelab", "normalizer": "generic"}]},
            "typesafe": {
                "enabled": True,
                "accept_cloud_data_boundary": True,
                "max_retries": 2,
                "backoff_base_seconds": 0,
            },
            "hermes": {"base_url": HERMES},
            "policy": {"version": "test-1"},
            "health": {"listen": ""},
        }
        for dotted, value in overrides.items():
            node = data
            *path, leaf = dotted.split("__")
            for key in path:
                node = node.setdefault(key, {})
            node[leaf] = value
        return Config.model_validate(data)

    return build


def jev_answers(
    *,
    category: str = "informational",
    confidence: float = 0.9,
    harm: float = 0.1,
    action: float = 0.3,
    digest: float = 0.5,
    noise: float = 0.3,
    relevance: float = 0.5,
) -> dict:
    rest = (1 - 0.9) / (len(CATEGORIES) - 1)
    probabilities = {c: (0.9 if c == category else rest) for c in CATEGORIES}
    return {
        "model": "jev-1.13.0",
        "answers": {
            "category": {
                "type": "choice",
                "choice": category,
                "probabilities": probabilities,
                "confidence": confidence,
            },
            "immediate_harm_if_ignored": {"type": "noul", "noul": harm},
            "human_action_useful": {"type": "noul", "noul": action},
            "digest_value": {"type": "noul", "noul": digest},
            "routine_noise": {"type": "noul", "noul": noise},
            "personal_relevance": {"type": "noul", "noul": relevance},
        },
        "usage": {"input_tokens": 400, "output_tokens": 60},
    }


class FakeServices:
    """MockTransport standing in for TypeSafe, Hermes, and ntfy publishing."""

    def __init__(self) -> None:
        self.jev: list[httpx.Response | dict] = []
        self.jev_default: dict | None = jev_answers()
        self.jev_requests: list[dict] = []
        self.hermes_status: list[int] = []
        self.hermes_requests: list[httpx.Request] = []
        self.ntfy_publishes: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.typesafe.ai":
            self.jev_requests.append(json.loads(request.content))
            item = self.jev.pop(0) if self.jev else self.jev_default
            return item if isinstance(item, httpx.Response) else httpx.Response(200, json=item)
        if request.url.path.startswith("/webhooks/"):
            self.hermes_requests.append(request)
            status = self.hermes_status.pop(0) if self.hermes_status else 202
            return httpx.Response(status, json={"status": "accepted"})
        if request.method == "POST" and request.url.path == "/":
            self.ntfy_publishes.append(json.loads(request.content))
            return httpx.Response(200, json={"id": "pub"})
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


@pytest.fixture
def services() -> FakeServices:
    return FakeServices()


def ntfy_line(
    mid: str,
    message: str = "hello",
    *,
    title: str = "",
    priority: int = 3,
    tags=(),
    ts: int | None = None,
    topic: str = "alerts",
) -> str:
    msg = {
        "id": mid,
        "time": ts if ts is not None else int(time.time()),
        "event": "message",
        "topic": topic,
        "message": message,
        "priority": priority,
    }
    if title:
        msg["title"] = title
    if tags:
        msg["tags"] = list(tags)
    return json.dumps(msg)


@pytest.fixture(autouse=True)
def secrets(monkeypatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "test-typesafe-key")
    monkeypatch.setenv("HERMES_WEBHOOK_SECRET", "test-hermes-secret")
