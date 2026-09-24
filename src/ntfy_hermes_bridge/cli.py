"""`ntfy-bridge` command line: run the bridge, inspect/label/replay decisions, evaluate policy changes."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
import time
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from .config import Config, ConfigError, load_config, secret
from .daemon import make_http
from .digest import run_due_digest
from .jev import JevClient
from .metrics import Metrics
from .models import SHADOW, Route, iso_from_unix, now_iso
from .pipeline import Context, Decision, Pipeline
from .store import AmbiguousRef, Store

ROUTES = [r.value for r in Route]
SEVERITY = {Route.DROP: 0, Route.DIGEST: 1, Route.REVIEW: 2, Route.NOTIFY_NOW: 3}
CRITICAL_SAFE_ROUTES = frozenset((Route.NOTIFY_NOW, Route.REVIEW))


# ---- helpers ------------------------------------------------------------------------------------


class Session:
    """Offline pipeline for CLI commands; opens a Jev client only when reclassification is requested."""

    def __init__(self, config: Config, *, classify: bool = False):
        self.config = config
        self.store = Store(config.bridge.database)
        self.http = None
        jev = None
        if classify:
            if not config.typesafe.enabled:
                raise ConfigError("--reclassify requires typesafe.enabled")
            self.http = make_http(config)
            jev = JevClient(self.http, secret(config.typesafe.api_key_env))
        self.pipeline = Pipeline(self.store, Metrics(), jev, Context.build(config))

    async def close(self) -> None:
        if self.http is not None:
            await self.http.aclose()
        self.store.close()


def _resolve(store: Store, ref: str) -> sqlite3.Row:
    try:
        return store.get_event(store.resolve_ref(ref))
    except (LookupError, AmbiguousRef) as exc:
        raise SystemExit(f"error: {exc}") from None


def _fmt_answers(answers_json: str | None) -> list[str]:
    if not answers_json:
        return []
    answers = json.loads(answers_json)
    category = answers["category"]
    top = sorted(category["probabilities"].items(), key=lambda kv: -kv[1])[:3]
    lines = [
        f"    category                   {category['choice']} (confidence {category['confidence']:.2f}; "
        + ", ".join(f"{k} {v:.2f}" for k, v in top)
        + ")"
    ]
    for key, value in answers.items():
        if key != "category":
            lines.append(f"    {key:<26} {value:.3f}")
    return lines


def _print_decision(row: sqlite3.Row | dict, title: str) -> None:
    print(f"{title}")
    print(f"  mode {row['mode']} · proposed {row['proposed_route']} · effective {row['effective_route']}")
    print(f"  deterministic rule: {row['deterministic_rule'] or '-'}")
    print(
        f"  versions: bridge {row['bridge_version']} · policy {row['policy_version']} ({row['policy_hash']}) · "
        f"questions {row['question_set_version']}"
    )
    if row["jev_model_requested"]:
        print(f"  jev: requested {row['jev_model_requested']} · returned {row['jev_model'] or '-'}")
    if row["jev_error"]:
        print(f"  jev error: {row['jev_error']}")
    if row["input_tokens"] is not None:
        print(
            f"  usage: {row['input_tokens']} in / {row['output_tokens']} out tokens · "
            f"${row['estimated_cost_usd']:.7f} · {row['jev_latency_ms']} ms"
        )
    answers = _fmt_answers(row["jev_answers_json"])
    if answers:
        print("  answers:")
        print("\n".join(answers))
    print(f"  thresholds: {row['thresholds_json']}")
    print("  reasons:")
    for reason in json.loads(row["reasons_json"]):
        print(f"    - {reason}")


# ---- commands -----------------------------------------------------------------------------------


def cmd_check(config: Config, args) -> int:
    print(f"config OK: mode={config.bridge.mode} policy={config.policy.version} hash={config.policy_hash()}")
    print(f"topics: {', '.join(t.name for t in config.ntfy.topics)}")
    print(f"jev: {config.typesafe.model if config.typesafe.enabled else 'disabled (local-only mode)'}")
    missing = []
    if config.typesafe.enabled and not secret(config.typesafe.api_key_env):
        missing.append(config.typesafe.api_key_env)
    if config.bridge.mode != "shadow" and not secret(config.hermes.secret_env):
        missing.append(config.hermes.secret_env)
    if config.ntfy.token_env and not secret(config.ntfy.token_env):
        missing.append(config.ntfy.token_env)
    if missing:
        print(f"missing secrets: {', '.join('$' + m for m in missing)}")
        return 1
    return 0


def cmd_list(config: Config, args) -> int:
    store = Store(config.bridge.database)
    rows = store.list_events(
        status=args.status, route=args.route, source=args.source, labeled=args.labeled, limit=args.limit
    )
    print(f"{'received':<20} {'ref':<18} {'source':<16} {'route':<10} {'status':<13} title")
    for row in rows:
        canonical = json.loads(row["canonical_json"]) if row["canonical_json"] else {}
        title = canonical.get("title") or canonical.get("source_entity") or ""
        print(
            f"{row['received_at'][:19]:<20} {row['message_id'][:18]:<18} {(row['source'] or '-')[:16]:<16} "
            f"{(row['route'] or '-'):<10} {row['status']:<13} {title[:60]}"
        )
    return 0


def cmd_explain(config: Config, args) -> int:
    store = Store(config.bridge.database)
    row = _resolve(store, args.ref)
    decisions = store.decisions_for(row["event_id"])
    if args.json:
        print(
            json.dumps(
                {
                    "event": dict(row) | {"raw_json": None},
                    "canonical": json.loads(row["canonical_json"]) if row["canonical_json"] else None,
                    "decisions": [dict(d) for d in decisions],
                    "outbox": [dict(o) for o in store.outbox_for_event(row["event_id"])],
                    "labels": [dict(label) for label in store.labels_for(row["event_id"])],
                },
                indent=2,
                default=str,
            )
        )
        return 0
    print(f"Event {row['event_id']}  (ref {row['message_id']})")
    print(f"  status {row['status']} · route {row['route'] or '-'} · synthetic {'yes' if row['synthetic'] else 'no'}")
    print(f"  received {row['received_at']} · occurred {row['occurred_at']} · raw sha256 {row['raw_sha256'][:16]}…")
    if row["error"]:
        print(f"  error: {row['error']}")
    if row["canonical_json"]:
        ev = json.loads(row["canonical_json"])
        print(
            f"  source {ev['source']} · entity {ev['source_entity']} · kind {ev['event_kind']} · normalizer {ev['normalizer']}"
        )
        print(f"  priority {ev['priority']} · tags {', '.join(ev['tags']) or '-'}")
        print(f"  repeat {ev['repeat_bucket']} · recency {ev['recency_bucket']} · fingerprint {ev['fingerprint']}")
        print(f"  title: {ev['title']}")
        message = ev["message"].replace("\n", "\n           ")
        print(f"  message: {message[:1200]}")
        if ev["click_url"]:
            print(f"  click: {ev['click_url']}")
    for decision in decisions:
        print()
        _print_decision(decision, f"Decision #{decision['id']} ({decision['kind']}, {decision['created_at']})")
    outbox = store.outbox_for_event(row["event_id"])
    digest = store.digest_item_for(row["event_id"])
    if outbox or digest:
        print("\nDelivery")
        for item in outbox:
            print(
                f"  outbox #{item['id']} {item['kind']} {item['status']} attempts={item['attempts']}"
                + (f" error={item['last_error']}" if item["last_error"] else "")
            )
        if digest:
            print(f"  digest: {digest['digest_id'] or 'queued for next digest'}")
    labels = store.labels_for(row["event_id"])
    if labels:
        print("\nLabels")
        for label in labels:
            flag = " critical" if label["critical"] else ""
            print(f"  {label['labeled_at']} {label['route']}{flag} {label['note']}")
    return 0


def cmd_label(config: Config, args) -> int:
    store = Store(config.bridge.database)
    row = _resolve(store, args.ref)
    store.add_label(row["event_id"], args.route, critical=args.critical, note=args.note or "")
    print(f"labeled {row['event_id']} as {args.route}{' (critical)' if args.critical else ''}")
    print("production thresholds are unchanged; run `ntfy-bridge eval` to measure the effect")
    return 0


async def _replay(config: Config, args) -> int:
    candidate = load_config(args.candidate) if args.candidate else config
    session = Session(candidate, classify=args.reclassify)
    try:
        store = session.store
        ctx = session.pipeline.ctx
        ctx.guardrail = await session.pipeline.compute_guardrail(ctx)
        for ref in args.refs:
            row = _resolve(store, ref)
            decision = await session.pipeline.replay(row, ctx, reclassify=args.reclassify)
            record = session.pipeline.record(decision, ctx)
            store.insert_replay_decision(row["event_id"], record)
            production = store.latest_decision(row["event_id"])
            print(f"== {row['event_id']}")
            if production is not None:
                print(
                    f"  production: proposed {production['proposed_route']} · effective {production['effective_route']}"
                )
            _print_decision(record, "  replay:")
    finally:
        await session.close()
    return 0


async def _evaluate(config: Config, args) -> int:
    baseline = Session(config)
    candidate = Session(load_config(args.candidate), classify=args.reclassify) if args.candidate else None
    try:
        labels = baseline.store.latest_labels()
        if not labels:
            print("no labeled events; label with `ntfy-bridge events label REF ROUTE [--critical]`")
            return 1
        results = []
        for label in labels:
            row = baseline.store.get_event(label["event_id"])
            base = await baseline.pipeline.replay(row, baseline.pipeline.ctx, reclassify=False)
            cand = (
                await candidate.pipeline.replay(row, candidate.pipeline.ctx, reclassify=args.reclassify)
                if candidate
                else None
            )
            results.append((label, base, cand))
        base_guard = await baseline.pipeline.compute_guardrail(baseline.pipeline.ctx)
        _report("current policy", config, [(label, base) for label, base, _ in results], base_guard)
        if candidate is None:
            return 0 if not base_guard.critical_dropped else 2
        cand_guard = await candidate.pipeline.compute_guardrail(candidate.pipeline.ctx)
        _report("candidate policy", candidate.config, [(label, cand) for label, _, cand in results], cand_guard)
        regressions = [
            (label, base, cand)
            for label, base, cand in results
            if (base.proposed == label["route"] and cand.proposed != label["route"])
            or (
                label["critical"]
                and base.proposed in CRITICAL_SAFE_ROUTES
                and cand.proposed not in CRITICAL_SAFE_ROUTES
            )
        ]
        fixes = sum(
            1 for label, base, cand in results if base.proposed != label["route"] and cand.proposed == label["route"]
        )
        print(f"\ncandidate vs current: {fixes} fixed, {len(regressions)} regressed")
        for label, base, cand in regressions:
            flag = " CRITICAL" if label["critical"] else ""
            print(
                f"  regression{flag}: {label['event_id']} label {label['route']} · {base.proposed} -> {cand.proposed}"
            )
        critical_regressed = any(label["critical"] for label, _, _ in regressions)
        return 2 if cand_guard.critical_dropped or critical_regressed else 0
    finally:
        await baseline.close()
        if candidate:
            await candidate.close()


def _report(title: str, config: Config, pairs: list[tuple[sqlite3.Row, Decision]], guard) -> None:
    total = len(pairs)
    correct = sum(1 for label, d in pairs if d.proposed == label["route"])
    confusion: Counter = Counter((label["route"], str(d.proposed)) for label, d in pairs)
    critical = [(label, d) for label, d in pairs if label["critical"]]
    crit_safe = sum(1 for _, d in critical if d.proposed in CRITICAL_SAFE_ROUTES)
    crit_dropped = sum(1 for _, d in critical if d.proposed is Route.DROP)
    notify = [(label, d) for label, d in pairs if d.proposed is Route.NOTIFY_NOW]
    notify_useful = sum(1 for label, _ in notify if label["route"] == Route.NOTIFY_NOW)
    under = sum(1 for label, d in pairs if SEVERITY[d.proposed] < SEVERITY[Route(label["route"])])
    print(f"\n{title}: policy {config.policy.version} ({config.policy_hash()})")
    print(f"  labeled events: {total} · exact route agreement {correct}/{total} ({correct / total:.0%})")
    print(f"  under-routed (less interruptive than label): {under}")
    if critical:
        print(
            f"  critical recall: {crit_safe}/{len(critical)} NOTIFY/REVIEW ({crit_safe / len(critical):.0%}) · "
            f"{crit_dropped} dropped"
        )
    if notify:
        print(f"  NOTIFY_NOW precision: {notify_useful}/{len(notify)} ({notify_useful / len(notify):.0%})")
    print(f"  DROP guardrail: {guard.describe()}")
    print("  confusion (label -> proposed):")
    for (label, proposed), n in sorted(confusion.items()):
        print(f"    {label:<10} -> {proposed:<10} {n}")


async def _import(config: Config, args) -> int:
    session = Session(config, classify=config.typesafe.enabled)
    imported: list[str] = []
    try:
        for number, line in enumerate(Path(args.file).read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                message = dict(item["message"])
            except (ValueError, KeyError, TypeError) as exc:
                raise SystemExit(
                    f"{args.file}:{number}: expected {{'message': {{...}}, 'label'?: ROUTE}}: {exc}"
                ) from None
            topic = item.get("topic") or "corpus"
            message.setdefault("id", f"syn-{uuid.uuid4().hex[:16]}")
            message.setdefault("time", int(time.time()))
            message.setdefault("event", "message")
            message["topic"] = topic
            received = now_iso()
            session.store.ingest(
                topic=topic,
                message_id=message["id"],
                message_time=int(message["time"]),
                raw_json=json.dumps(message),
                occurred_at=iso_from_unix(message["time"]),
                received_at=received,
                synthetic=True,
                advance_cursor=False,
            )
            event_id = f"ntfy:{topic}:{message['id']}"
            if item.get("label"):
                if item["label"] not in ROUTES:
                    raise SystemExit(f"{args.file}:{number}: label must be one of {ROUTES}")
                session.store.add_label(
                    event_id, item["label"], critical=bool(item.get("critical")), note=item.get("note", "")
                )
            imported.append(event_id)
        for row in session.store.claim_received(len(imported), event_ids=imported):
            decision = await session.pipeline.process(row)
            route = f"{decision.proposed}" if decision else "quarantined"
            print(f"{row['event_id']}: proposed {route}")
    finally:
        await session.close()
    print(f"imported {len(imported)} synthetic events (never delivered)")
    return 0


def cmd_outbox_list(config: Config, args) -> int:
    store = Store(config.bridge.database)
    for row in store.list_outbox(status=args.status, limit=args.limit):
        print(
            f"#{row['id']:<6} {row['kind']:<14} {row['status']:<9} attempts={row['attempts']:<3} "
            f"{row['request_id'][:48]:<48} {(row['last_error'] or '')[:60]}"
        )
    return 0


def cmd_outbox_retry(config: Config, args) -> int:
    store = Store(config.bridge.database)
    count = store.requeue_dead(None if args.all_dead else args.ids)
    print(f"requeued {count} dead letter(s)")
    return 0


def cmd_digest_flush(config: Config, args) -> int:
    store = Store(config.bridge.database)
    parts = run_due_digest(store, config, datetime.now(UTC), force=True)
    print(f"enqueued {parts} digest part(s)" if parts else "no pending digest items")
    return 0


# ---- entry point --------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ntfy-bridge", description=__doc__)
    parser.add_argument(
        "-c", "--config", default=os.environ.get("NTFY_BRIDGE_CONFIG", "config.toml"), help="config TOML path"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the bridge")
    sub.add_parser("check-config", help="validate configuration and secrets")

    events = sub.add_parser("events", help="inspect, label, replay, and import events").add_subparsers(
        dest="events_command", required=True
    )
    p = events.add_parser("list", help="list recent events")
    p.add_argument("--status")
    p.add_argument("--route", choices=[*ROUTES, SHADOW])
    p.add_argument("--source")
    p.add_argument("--labeled", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p = events.add_parser("explain", help="show the full decision trace for an event")
    p.add_argument("ref", help="event ID or ntfy message ID")
    p.add_argument("--json", action="store_true")
    p = events.add_parser("label", help="record the correct route (stored separately from decisions)")
    p.add_argument("ref")
    p.add_argument("route", choices=ROUTES)
    p.add_argument("--critical", action="store_true", help="seeded/real critical case for recall guardrails")
    p.add_argument("--note")
    p = events.add_parser("replay", help="recompute decisions under the current or a candidate policy")
    p.add_argument("refs", nargs="+")
    p.add_argument("--candidate", help="candidate config TOML to evaluate instead of --config")
    p.add_argument("--reclassify", action="store_true", help="call Jev again instead of reusing stored answers")
    p = events.add_parser("import", help="import synthetic/adversarial corpus events from JSONL")
    p.add_argument("file")

    p = sub.add_parser("eval", help="replay the labeled corpus; compare a candidate policy for regressions")
    p.add_argument("--candidate")
    p.add_argument("--reclassify", action="store_true")

    outbox = sub.add_parser("outbox", help="inspect and retry deliveries").add_subparsers(
        dest="outbox_command", required=True
    )
    p = outbox.add_parser("list")
    p.add_argument("--status", choices=["pending", "delivered", "dead"])
    p.add_argument("--limit", type=int, default=50)
    p = outbox.add_parser("retry", help="requeue dead letters")
    p.add_argument("ids", nargs="*", type=int)
    p.add_argument("--all-dead", action="store_true")

    digest = sub.add_parser("digest", help="digest operations").add_subparsers(dest="digest_command", required=True)
    digest.add_parser("flush", help="enqueue a digest of all pending items now")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            from .daemon import run

            return run(Path(args.config))
        config = load_config(args.config)
        match (
            args.command,
            getattr(args, "events_command", None)
            or getattr(args, "outbox_command", None)
            or getattr(args, "digest_command", None),
        ):
            case "check-config", _:
                return cmd_check(config, args)
            case "events", "list":
                return cmd_list(config, args)
            case "events", "explain":
                return cmd_explain(config, args)
            case "events", "label":
                return cmd_label(config, args)
            case "events", "replay":
                return asyncio.run(_replay(config, args))
            case "events", "import":
                return asyncio.run(_import(config, args))
            case "eval", _:
                return asyncio.run(_evaluate(config, args))
            case "outbox", "list":
                return cmd_outbox_list(config, args)
            case "outbox", "retry":
                if not args.ids and not args.all_dead:
                    raise SystemExit("error: pass outbox IDs or --all-dead")
                return cmd_outbox_retry(config, args)
            case "digest", "flush":
                return cmd_digest_flush(config, args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1
