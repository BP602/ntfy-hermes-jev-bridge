from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS cursors (
    topic TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    message_time INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    topic TEXT NOT NULL,
    message_id TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    synthetic INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    source TEXT,
    source_entity TEXT,
    event_kind TEXT,
    fingerprint TEXT,
    canonical_json TEXT,
    route TEXT,
    error TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_status ON events(status, received_at);
CREATE INDEX IF NOT EXISTS events_fingerprint ON events(fingerprint, received_at);
CREATE INDEX IF NOT EXISTS events_entity ON events(source, source_entity, received_at);
CREATE INDEX IF NOT EXISTS events_message ON events(message_id);

CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('production', 'replay')),
    created_at TEXT NOT NULL,
    mode TEXT NOT NULL,
    bridge_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    question_set_version TEXT NOT NULL,
    thresholds_json TEXT NOT NULL,
    jev_model_requested TEXT,
    jev_model TEXT,
    jev_state_json TEXT,
    jev_answers_json TEXT,
    jev_error TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    estimated_cost_usd REAL,
    jev_latency_ms INTEGER,
    deterministic_rule TEXT,
    proposed_route TEXT NOT NULL,
    effective_route TEXT NOT NULL,
    reasons_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decisions_event ON decisions(event_id, kind, id);

CREATE TABLE IF NOT EXISTS labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    route TEXT NOT NULL,
    critical INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    labeled_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS labels_event ON labels(event_id, id);

CREATE TABLE IF NOT EXISTS outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('compose', 'review', 'digest', 'fallback_ntfy')),
    event_id TEXT REFERENCES events(event_id) ON DELETE SET NULL,
    digest_id TEXT,
    request_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    critical INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(status, next_attempt_at);

CREATE TABLE IF NOT EXISTS digest_items (
    event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
    queued_at TEXT NOT NULL,
    digest_id TEXT
);
CREATE INDEX IF NOT EXISTS digest_items_digest ON digest_items(digest_id);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    raw TEXT NOT NULL,
    error TEXT NOT NULL,
    received_at TEXT NOT NULL
);
"""

# Event lifecycle. Terminal statuses are the only ones retention may prune.
RECEIVED = "received"
PROCESSING = "processing"
QUEUED = "queued"  # waiting in the outbox for Hermes
QUEUED_DIGEST = "queued_digest"
TERMINAL_STATUSES = ("dropped", "delivered", "digested", "dead_letter", "shadow", "quarantined")

MAX_PROCESS_ATTEMPTS = 5


@dataclass(frozen=True, slots=True)
class OutboxInsert:
    kind: str
    request_id: str
    payload: dict
    critical: bool = False
    digest_id: str | None = None


class AmbiguousRef(LookupError):
    pass


class Store:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        if path != ":memory:":
            os.chmod(path, 0o600)

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # ---- meta -------------------------------------------------------------------------------

    def get_meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ---- ingest -----------------------------------------------------------------------------

    def get_cursor(self, topic: str) -> str | None:
        row = self.conn.execute("SELECT message_id FROM cursors WHERE topic = ?", (topic,)).fetchone()
        return row["message_id"] if row else None

    def ingest(
        self,
        *,
        topic: str,
        message_id: str,
        message_time: int,
        raw_json: str,
        occurred_at: str,
        received_at: str,
        synthetic: bool = False,
        advance_cursor: bool = True,
        event_id: str | None = None,
    ) -> bool:
        """Persist an accepted message and advance the topic cursor in one transaction.

        Returns False when the event ID was already persisted (exact duplicate / replay overlap).
        """
        event_id = event_id or f"ntfy:{topic}:{message_id}"
        raw_sha256 = hashlib.sha256(raw_json.encode()).hexdigest()
        with self.tx() as conn:
            cur = conn.execute(
                """INSERT OR IGNORE INTO events(event_id, topic, message_id, raw_json, raw_sha256, occurred_at,
                       received_at, synthetic, status, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event_id,
                    topic,
                    message_id,
                    raw_json,
                    raw_sha256,
                    occurred_at,
                    received_at,
                    int(synthetic),
                    RECEIVED,
                    received_at,
                ),
            )
            if advance_cursor:
                conn.execute(
                    """INSERT INTO cursors(topic, message_id, message_time, updated_at) VALUES (?, ?, ?, ?)
                       ON CONFLICT(topic) DO UPDATE SET message_id = excluded.message_id,
                           message_time = excluded.message_time, updated_at = excluded.updated_at""",
                    (topic, message_id, message_time, received_at),
                )
        return cur.rowcount == 1

    def quarantine_raw(self, topic: str, raw: str, error: str) -> None:
        self.conn.execute(
            "INSERT INTO quarantine(topic, raw, error, received_at) VALUES (?, ?, ?, ?)",
            (topic, raw[:20_000], error, now_iso()),
        )

    # ---- processing claims ------------------------------------------------------------------

    def reset_processing(self) -> int:
        return self.conn.execute(
            "UPDATE events SET status = ?, updated_at = ? WHERE status = ?", (RECEIVED, now_iso(), PROCESSING)
        ).rowcount

    def claim_received(self, limit: int, *, event_ids: Sequence[str] | None = None) -> list[sqlite3.Row]:
        with self.tx() as conn:
            if event_ids is None:
                rows = conn.execute(
                    "SELECT * FROM events WHERE status = ? ORDER BY received_at, event_id LIMIT ?", (RECEIVED, limit)
                ).fetchall()
            else:
                marks = ",".join("?" * len(event_ids))
                rows = conn.execute(
                    f"SELECT * FROM events WHERE status = ? AND event_id IN ({marks}) ORDER BY received_at",
                    (RECEIVED, *event_ids),
                ).fetchall()
            conn.executemany(
                "UPDATE events SET status = ?, updated_at = ? WHERE event_id = ?",
                [(PROCESSING, now_iso(), r["event_id"]) for r in rows],
            )
        return rows

    def release_failed(self, event_id: str, error: str) -> str:
        """Return a claimed event after an unexpected processing error; quarantine after repeated failures."""
        with self.tx() as conn:
            row = conn.execute("SELECT attempts FROM events WHERE event_id = ?", (event_id,)).fetchone()
            attempts = row["attempts"] + 1
            status = "quarantined" if attempts >= MAX_PROCESS_ATTEMPTS else RECEIVED
            conn.execute(
                "UPDATE events SET status = ?, attempts = ?, error = ?, updated_at = ? WHERE event_id = ?",
                (status, attempts, error[:2000], now_iso(), event_id),
            )
        return status

    def mark_quarantined(self, event_id: str, error: str) -> None:
        self.conn.execute(
            "UPDATE events SET status = 'quarantined', error = ?, updated_at = ? WHERE event_id = ?",
            (error[:2000], now_iso(), event_id),
        )

    # ---- history for dedupe/flapping/cooldown -----------------------------------------------

    def fingerprint_seen(self, fingerprint: str, *, since: str, before: str, exclude: str) -> bool:
        row = self.conn.execute(
            """SELECT 1 FROM events WHERE fingerprint = ? AND received_at >= ? AND received_at < ?
                   AND event_id != ? AND synthetic = 0 LIMIT 1""",
            (fingerprint, since, before, exclude),
        ).fetchone()
        return row is not None

    def entity_fingerprints(self, source: str, entity: str, *, since: str, before: str, exclude: str) -> list[str]:
        rows = self.conn.execute(
            """SELECT fingerprint FROM events WHERE source = ? AND source_entity = ? AND received_at >= ?
                   AND received_at < ? AND event_id != ? AND synthetic = 0 AND fingerprint IS NOT NULL
               ORDER BY received_at, event_id""",
            (source, entity, since, before, exclude),
        ).fetchall()
        return [r["fingerprint"] for r in rows]

    def recent_hermes_event(self, fingerprint: str, *, since: str, before: str, exclude: str) -> sqlite3.Row | None:
        return self.conn.execute(
            """SELECT event_id, received_at, route FROM events WHERE fingerprint = ? AND received_at >= ?
                   AND received_at < ? AND event_id != ? AND synthetic = 0 AND route IN ('NOTIFY_NOW', 'REVIEW')
               ORDER BY received_at DESC LIMIT 1""",
            (fingerprint, since, before, exclude),
        ).fetchone()

    # ---- decisions --------------------------------------------------------------------------

    def _insert_decision(self, conn: sqlite3.Connection, record: dict) -> int:
        columns = ",".join(record)
        marks = ",".join("?" * len(record))
        return conn.execute(f"INSERT INTO decisions({columns}) VALUES ({marks})", tuple(record.values())).lastrowid

    def commit_production_decision(
        self,
        *,
        event_id: str,
        canonical: dict,
        record: dict,
        status: str,
        route: str,
        outbox: OutboxInsert | None,
        digest: bool,
    ) -> int:
        """Atomically store the decision, the event's next state, and any outbox/digest work."""
        now = now_iso()
        with self.tx() as conn:
            decision_id = self._insert_decision(conn, {**record, "event_id": event_id, "kind": "production"})
            conn.execute(
                """UPDATE events SET status = ?, route = ?, source = ?, source_entity = ?, event_kind = ?,
                       fingerprint = ?, canonical_json = ?, error = NULL, updated_at = ? WHERE event_id = ?""",
                (
                    status,
                    route,
                    canonical["source"],
                    canonical["source_entity"],
                    canonical["event_kind"],
                    canonical["fingerprint"],
                    json.dumps(canonical),
                    now,
                    event_id,
                ),
            )
            if outbox is not None:
                self._enqueue(conn, outbox, event_id=event_id, now=now)
            if digest:
                conn.execute("INSERT OR IGNORE INTO digest_items(event_id, queued_at) VALUES (?, ?)", (event_id, now))
        return decision_id

    def insert_replay_decision(self, event_id: str, record: dict) -> int:
        with self.tx() as conn:
            return self._insert_decision(conn, {**record, "event_id": event_id, "kind": "replay"})

    def latest_decision(self, event_id: str, kind: str = "production") -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM decisions WHERE event_id = ? AND kind = ? ORDER BY id DESC LIMIT 1", (event_id, kind)
        ).fetchone()

    def decisions_for(self, event_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM decisions WHERE event_id = ? ORDER BY id", (event_id,)).fetchall()

    # ---- events queries ---------------------------------------------------------------------

    def get_event(self, event_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()

    def resolve_ref(self, ref: str) -> str:
        if self.get_event(ref) is not None:
            return ref
        rows = self.conn.execute("SELECT event_id FROM events WHERE message_id = ? LIMIT 2", (ref,)).fetchall()
        if not rows:
            raise LookupError(f"no event matches {ref!r}")
        if len(rows) > 1:
            raise AmbiguousRef(f"{ref!r} matches several topics; use the full event ID")
        return rows[0]["event_id"]

    def list_events(
        self,
        *,
        status: str | None = None,
        route: str | None = None,
        source: str | None = None,
        labeled: bool = False,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        clauses, params = [], []
        for column, value in (("status", status), ("route", route), ("source", source)):
            if value:
                clauses.append(f"e.{column} = ?")
                params.append(value)
        if labeled:
            clauses.append("EXISTS (SELECT 1 FROM labels l WHERE l.event_id = e.event_id)")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return self.conn.execute(
            f"SELECT e.* FROM events e {where} ORDER BY e.received_at DESC LIMIT ?", (*params, limit)
        ).fetchall()

    # ---- labels -----------------------------------------------------------------------------

    def add_label(self, event_id: str, route: str, *, critical: bool, note: str) -> None:
        self.conn.execute(
            "INSERT INTO labels(event_id, route, critical, note, labeled_at) VALUES (?, ?, ?, ?, ?)",
            (event_id, route, int(critical), note, now_iso()),
        )

    def labels_for(self, event_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM labels WHERE event_id = ? ORDER BY id", (event_id,)).fetchall()

    def latest_labels(self) -> list[sqlite3.Row]:
        """The evaluation dataset: the most recent label of every labeled event."""
        return self.conn.execute(
            """SELECT l.* FROM labels l
               JOIN (SELECT event_id, MAX(id) AS id FROM labels GROUP BY event_id) latest ON latest.id = l.id
               ORDER BY l.event_id"""
        ).fetchall()

    # ---- outbox -----------------------------------------------------------------------------

    def _enqueue(self, conn: sqlite3.Connection, item: OutboxInsert, *, event_id: str | None, now: str) -> bool:
        cur = conn.execute(
            """INSERT OR IGNORE INTO outbox(kind, event_id, digest_id, request_id, payload_json, critical,
                   next_attempt_at, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                item.kind,
                event_id,
                item.digest_id,
                item.request_id,
                json.dumps(item.payload, ensure_ascii=False),
                int(item.critical),
                now,
                now,
                now,
            ),
        )
        return cur.rowcount == 1

    def enqueue(self, item: OutboxInsert, *, event_id: str | None = None) -> bool:
        with self.tx() as conn:
            return self._enqueue(conn, item, event_id=event_id, now=now_iso())

    def due_outbox(self, now: str, limit: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM outbox WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at, id LIMIT ?",
            (now, limit),
        ).fetchall()

    def next_outbox_due(self) -> str | None:
        row = self.conn.execute("SELECT MIN(next_attempt_at) AS due FROM outbox WHERE status = 'pending'").fetchone()
        return row["due"]

    def outbox_delivered(self, row: sqlite3.Row) -> None:
        now = now_iso()
        with self.tx() as conn:
            conn.execute(
                "UPDATE outbox SET status = 'delivered', attempts = attempts + 1, last_error = NULL, updated_at = ? "
                "WHERE id = ?",
                (now, row["id"]),
            )
            if row["kind"] in ("compose", "review") and row["event_id"]:
                conn.execute(
                    "UPDATE events SET status = 'delivered', updated_at = ? WHERE event_id = ? AND status = ?",
                    (now, row["event_id"], QUEUED),
                )
            elif row["kind"] == "digest":
                conn.execute(
                    f"""UPDATE events SET status = 'digested', updated_at = ?
                        WHERE status = '{QUEUED_DIGEST}'
                          AND event_id IN (SELECT event_id FROM digest_items WHERE digest_id = ?)""",
                    (now, row["digest_id"]),
                )

    def outbox_retry(self, row_id: int, *, error: str, next_attempt_at: str) -> None:
        self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ?, updated_at = ? WHERE id = ?",
            (error[:2000], next_attempt_at, now_iso(), row_id),
        )

    def outbox_dead(self, row: sqlite3.Row, *, error: str) -> None:
        now = now_iso()
        with self.tx() as conn:
            conn.execute(
                "UPDATE outbox SET status = 'dead', attempts = attempts + 1, last_error = ?, updated_at = ? WHERE id = ?",
                (error[:2000], now, row["id"]),
            )
            if row["kind"] in ("compose", "review") and row["event_id"]:
                conn.execute(
                    "UPDATE events SET status = 'dead_letter', updated_at = ? WHERE event_id = ? AND status = ?",
                    (now, row["event_id"], QUEUED),
                )
            elif row["kind"] == "digest":
                conn.execute(
                    f"""UPDATE events SET status = 'dead_letter', updated_at = ?
                        WHERE status = '{QUEUED_DIGEST}'
                          AND event_id IN (SELECT event_id FROM digest_items WHERE digest_id = ?)""",
                    (now, row["digest_id"]),
                )

    def list_outbox(self, *, status: str | None = None, limit: int = 50) -> list[sqlite3.Row]:
        if status:
            return self.conn.execute(
                "SELECT * FROM outbox WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit)
            ).fetchall()
        return self.conn.execute("SELECT * FROM outbox ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def outbox_for_event(self, event_id: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM outbox WHERE event_id = ? ORDER BY id", (event_id,)).fetchall()

    def requeue_dead(self, ids: Sequence[int] | None) -> int:
        """Move dead letters back to pending. `None` requeues every dead letter."""
        now = now_iso()
        with self.tx() as conn:
            if ids is None:
                rows = conn.execute("SELECT id, kind, event_id, digest_id FROM outbox WHERE status = 'dead'").fetchall()
            else:
                marks = ",".join("?" * len(ids))
                rows = conn.execute(
                    f"SELECT id, kind, event_id, digest_id FROM outbox WHERE status = 'dead' AND id IN ({marks})",
                    tuple(ids),
                ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE outbox SET status = 'pending', attempts = 0, next_attempt_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, row["id"]),
                )
                if row["kind"] in ("compose", "review") and row["event_id"]:
                    conn.execute(
                        "UPDATE events SET status = ?, updated_at = ? WHERE event_id = ? AND status = 'dead_letter'",
                        (QUEUED, now, row["event_id"]),
                    )
                elif row["kind"] == "digest":
                    conn.execute(
                        """UPDATE events SET status = ?, updated_at = ? WHERE status = 'dead_letter'
                              AND event_id IN (SELECT event_id FROM digest_items WHERE digest_id = ?)""",
                        (QUEUED_DIGEST, now, row["digest_id"]),
                    )
        return len(rows)

    # ---- digest -----------------------------------------------------------------------------

    def pending_digest_items(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT d.event_id, d.queued_at, e.canonical_json, e.route, e.received_at,
                      (SELECT jev_answers_json FROM decisions x WHERE x.event_id = d.event_id AND x.kind = 'production'
                       ORDER BY x.id DESC LIMIT 1) AS jev_answers_json
               FROM digest_items d JOIN events e ON e.event_id = d.event_id
               WHERE d.digest_id IS NULL ORDER BY e.received_at"""
        ).fetchall()

    def digest_item_for(self, event_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM digest_items WHERE event_id = ?", (event_id,)).fetchone()

    def commit_digest(self, parts: Sequence[tuple[OutboxInsert, Sequence[str]]]) -> int:
        now = now_iso()
        inserted = 0
        with self.tx() as conn:
            for item, event_ids in parts:
                if not self._enqueue(conn, item, event_id=None, now=now):
                    continue
                conn.executemany(
                    "UPDATE digest_items SET digest_id = ? WHERE event_id = ? AND digest_id IS NULL",
                    [(item.digest_id, event_id) for event_id in event_ids],
                )
                inserted += 1
        return inserted

    # ---- health / metrics -------------------------------------------------------------------

    def counts(self) -> dict[str, float]:
        c = self.conn
        oldest = c.execute("SELECT MIN(created_at) AS t FROM outbox WHERE status = 'pending'").fetchone()["t"]
        undecided = c.execute(
            "SELECT COUNT(*) AS n FROM events WHERE status IN (?, ?)", (RECEIVED, PROCESSING)
        ).fetchone()["n"]
        age = (datetime.now(UTC) - datetime.fromisoformat(oldest)).total_seconds() if oldest else 0.0
        return {
            "events_undecided": undecided,
            "events_quarantined": c.execute("SELECT COUNT(*) AS n FROM events WHERE status = 'quarantined'").fetchone()[
                "n"
            ],
            "quarantine_raw": c.execute("SELECT COUNT(*) AS n FROM quarantine").fetchone()["n"],
            "outbox_pending": c.execute("SELECT COUNT(*) AS n FROM outbox WHERE status = 'pending'").fetchone()["n"],
            "outbox_dead": c.execute("SELECT COUNT(*) AS n FROM outbox WHERE status = 'dead'").fetchone()["n"],
            "outbox_oldest_pending_seconds": age,
            "digest_pending": c.execute("SELECT COUNT(*) AS n FROM digest_items WHERE digest_id IS NULL").fetchone()[
                "n"
            ],
        }

    def prune(self, retention_days: int) -> int:
        """Delete terminal, unlabeled events older than the retention window."""
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat(timespec="microseconds")
        marks = ",".join("?" * len(TERMINAL_STATUSES))
        with self.tx() as conn:
            conn.execute(
                f"""DELETE FROM outbox WHERE status != 'pending' AND updated_at < ?
                      AND NOT EXISTS (
                          SELECT 1 FROM digest_items d JOIN events e ON e.event_id = d.event_id
                          WHERE outbox.kind = 'digest' AND outbox.status = 'dead'
                            AND d.digest_id = outbox.digest_id AND e.status NOT IN ({marks})
                      )""",
                (cutoff, *TERMINAL_STATUSES),
            )
            conn.execute("DELETE FROM quarantine WHERE received_at < ?", (cutoff,))
            return conn.execute(
                f"""DELETE FROM events WHERE status IN ({marks}) AND received_at < ?
                      AND NOT EXISTS (SELECT 1 FROM labels l WHERE l.event_id = events.event_id)
                      AND NOT EXISTS (SELECT 1 FROM digest_items d WHERE d.event_id = events.event_id
                                      AND d.digest_id IS NULL)
                      AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.event_id = events.event_id
                                      AND o.status = 'pending')""",
                (*TERMINAL_STATUSES, cutoff),
            ).rowcount
