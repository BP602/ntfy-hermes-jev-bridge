"""In-process counters rendered in Prometheus text exposition format."""

from __future__ import annotations

from bisect import bisect_left
from collections import defaultdict

PREFIX = "ntfy_bridge_"
LATENCY_BUCKETS_MS = (100, 250, 500, 1000, 2000, 5000, 10000)

HELP = {
    "events_ingested_total": "Accepted ntfy messages persisted to the inbox",
    "events_duplicate_total": "ntfy messages already persisted (replay overlap)",
    "events_quarantined_total": "Messages that failed validation or normalization",
    "ntfy_truncated_replays_total": "ntfy replays that reported X-Messages-Truncated",
    "decisions_total": "Production decisions by proposed and effective route",
    "redactions_total": "Redactions applied, by kind",
    "jev_requests_total": "Jev classification requests by outcome",
    "jev_state_blocked_total": "Jev requests blocked by the outbound redaction guard",
    "jev_input_tokens_total": "Jev input tokens",
    "jev_output_tokens_total": "Jev output tokens",
    "jev_estimated_cost_usd_total": "Estimated Jev cost in USD",
    "deliveries_total": "Outbox delivery attempts by kind and outcome",
    "digests_total": "Digest parts enqueued",
    "config_reloads_total": "Config reload attempts by outcome",
    "health_alerts_total": "Bridge health alerts raised, by kind",
}


class Metrics:
    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._latency = [0] * (len(LATENCY_BUCKETS_MS) + 1)
        self._latency_sum = 0.0

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        self._counters[(name, tuple(sorted(labels.items())))] += value

    def value(self, name: str, **labels: str) -> float:
        return self._counters.get((name, tuple(sorted(labels.items()))), 0.0)

    def observe_latency(self, ms: float) -> None:
        self._latency[bisect_left(LATENCY_BUCKETS_MS, ms)] += 1
        self._latency_sum += ms

    def render(self, gauges: dict[str, float]) -> str:
        lines: list[str] = []
        by_name: dict[str, list[tuple[tuple[tuple[str, str], ...], float]]] = defaultdict(list)
        for (name, labels), value in self._counters.items():
            by_name[name].append((labels, value))
        for name in sorted(by_name):
            lines.append(f"# HELP {PREFIX}{name} {HELP.get(name, name)}")
            lines.append(f"# TYPE {PREFIX}{name} counter")
            for labels, value in sorted(by_name[name]):
                lines.append(f"{PREFIX}{name}{_labels(labels)} {value:g}")
        hist = f"{PREFIX}jev_latency_ms"
        lines += [f"# HELP {hist} Jev request latency", f"# TYPE {hist} histogram"]
        cumulative = 0
        for bound, count in zip((*map(str, LATENCY_BUCKETS_MS), "+Inf"), self._latency, strict=True):
            cumulative += count
            lines.append(f'{hist}_bucket{{le="{bound}"}} {cumulative}')
        lines += [f"{hist}_sum {self._latency_sum:g}", f"{hist}_count {cumulative}"]
        for name, value in sorted(gauges.items()):
            lines += [f"# TYPE {PREFIX}{name} gauge", f"{PREFIX}{name} {value:g}"]
        return "\n".join(lines) + "\n"


def _labels(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    body = ",".join(
        f'{k}="{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"' for k, v in labels
    )
    return "{" + body + "}"
