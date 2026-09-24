import os
import stat
from datetime import UTC, datetime, timedelta

from ntfy_hermes_bridge.store import (
    PROCESSING,
    QUEUED,
    QUEUED_DIGEST,
    RECEIVED,
    TERMINAL_STATUSES,
    Store,
)


def file_mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_database_and_live_wal_are_owner_only_with_permissive_umask(tmp_path):
    database_dir = tmp_path / "database"
    database_dir.mkdir(mode=0o777)
    database_dir.chmod(0o777)
    database = database_dir / "bridge.db"
    secret = "raw WAL payload must remain private"

    previous_umask = os.umask(0)
    store = None
    reopened = None
    try:
        store = Store(str(database))
        store.conn.execute("PRAGMA wal_autocheckpoint=0")
        timestamp = datetime.now(UTC).isoformat(timespec="microseconds")
        store.ingest(
            topic="security",
            message_id="wal-secret",
            message_time=1,
            raw_json=secret,
            occurred_at=timestamp,
            received_at=timestamp,
        )

        wal = database.with_name(f"{database.name}-wal")
        shm = database.with_name(f"{database.name}-shm")
        assert secret.encode() in wal.read_bytes()
        assert [file_mode(path) for path in (database, wal, shm)] == [0o600, 0o600, 0o600]
        assert file_mode(database_dir) == 0o777

        for path in (database, wal, shm):
            path.chmod(0o666)
        reopened = Store(str(database))
        assert [file_mode(path) for path in (database, wal, shm)] == [0o600, 0o600, 0o600]
    finally:
        if reopened is not None:
            reopened.close()
        if store is not None:
            store.close()
        os.umask(previous_umask)


def test_counts_include_every_nonterminal_status_and_oldest_age(tmp_path):
    store = Store(str(tmp_path / "bridge.db"))
    try:
        now = datetime.now(UTC)
        statuses = (
            (RECEIVED, now - timedelta(seconds=20)),
            (PROCESSING, now - timedelta(seconds=30)),
            (QUEUED, now - timedelta(seconds=40)),
            (QUEUED_DIGEST, now - timedelta(seconds=90)),
            *((status, now - timedelta(days=2)) for status in TERMINAL_STATUSES),
        )
        for index, (status, received_at) in enumerate(statuses):
            timestamp = received_at.isoformat(timespec="microseconds")
            store.ingest(
                topic="metrics",
                message_id=str(index),
                message_time=index,
                raw_json="{}",
                occurred_at=timestamp,
                received_at=timestamp,
            )
            store.conn.execute(
                "UPDATE events SET status = ? WHERE event_id = ?",
                (status, f"ntfy:metrics:{index}"),
            )

        counts = store.counts()
        assert counts["events_undecided"] == 2
        assert counts["events_nonterminal"] == 4
        assert 89 <= counts["events_oldest_nonterminal_seconds"] < 100
        assert counts["digest_pending"] == 0
    finally:
        store.close()
