"""
Temporal Event Store.

Persists events to SQLite (swappable for any other backend behind the same
interface — see `EventStoreBackend`). Four logical layers are kept apart:

  raw          -> untouched connector payload, before normalization
  normalized   -> CanonicalSecurityEvent, one row, immutable once written
  enriched     -> normalized event plus enrichment metadata (append-only,
                   versioned; never rewrites the normalized row)
  derived      -> anything computed *about* events (correlation, causality,
                   episode membership, detections) referencing event_ids

Once a normalized event row exists it is never UPDATEd or DELETEd from this
store; corrections are modeled as new derived/enriched records that
reference the original, so history stays trustworthy.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.event_store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    raw_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    received_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL,
    event_time TEXT NOT NULL,
    receive_time TEXT NOT NULL,
    host_id TEXT,
    process_id TEXT,
    container_id TEXT,
    user_identity TEXT,
    actor_entity_id TEXT,
    target_entity_id TEXT,
    correlation_id TEXT,
    session_id TEXT,
    parent_event_id TEXT,
    content_hash TEXT NOT NULL,
    importance_score REAL DEFAULT 0.0,
    importance_tier TEXT DEFAULT 'low',
    confidence REAL DEFAULT 1.0,
    body TEXT NOT NULL,
    inserted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_norm_event_time ON normalized_events(event_time);
CREATE INDEX IF NOT EXISTS idx_norm_host ON normalized_events(host_id);
CREATE INDEX IF NOT EXISTS idx_norm_hash ON normalized_events(content_hash);
CREATE INDEX IF NOT EXISTS idx_norm_actor ON normalized_events(actor_entity_id);
CREATE INDEX IF NOT EXISTS idx_norm_target ON normalized_events(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_norm_correlation ON normalized_events(correlation_id);

CREATE TABLE IF NOT EXISTS enrichments (
    enrichment_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    enrichment_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(event_id) REFERENCES normalized_events(event_id)
);
CREATE INDEX IF NOT EXISTS idx_enrich_event ON enrichments(event_id);

CREATE TABLE IF NOT EXISTS derived_artifacts (
    artifact_id TEXT PRIMARY KEY,
    artifact_type TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    payload TEXT NOT NULL,
    algorithm_version TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_derived_type ON derived_artifacts(artifact_type);

CREATE TABLE IF NOT EXISTS hash_chain (
    host_id TEXT PRIMARY KEY,
    last_hash TEXT NOT NULL,
    length INTEGER NOT NULL DEFAULT 0
);
"""


class DuplicateEventError(Exception):
    pass


class ImmutableEventError(Exception):
    pass


class EventStore:
    """SQLite-backed implementation. Thread-safe via a single write lock."""

    def __init__(self, db_path: str | Path = "data/phantom_memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        with self._lock:
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    # ---- raw layer ----------------------------------------------------- #
    def write_raw(self, raw_id: str, source: str, payload: dict[str, Any], received_at: datetime) -> str:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO raw_events (raw_id, source, received_at, payload) VALUES (?,?,?,?)",
                (raw_id, source, received_at.isoformat(), json.dumps(payload, default=str)),
            )
        return raw_id

    # ---- normalized layer (immutable) ----------------------------------- #
    def write_normalized(self, event: CanonicalSecurityEvent) -> CanonicalSecurityEvent:
        event = event.finalize()
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT event_id FROM normalized_events WHERE event_id = ?", (event.event_id,)
            ).fetchone()
            if existing:
                raise ImmutableEventError(
                    f"Event {event.event_id} already exists and normalized events are immutable."
                )
            conn.execute(
                """INSERT INTO normalized_events
                (event_id, event_type, event_category, event_time, receive_time, host_id,
                 process_id, container_id, user_identity, actor_entity_id, target_entity_id,
                 correlation_id, session_id, parent_event_id, content_hash, importance_score,
                 importance_tier, confidence, body, inserted_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id,
                    event.event_type,
                    event.event_category.value,
                    event.timestamps.event_time.isoformat(),
                    event.timestamps.receive_time.isoformat(),
                    event.host_id,
                    event.process_id,
                    event.container_id,
                    event.user_identity,
                    event.actor_entity_id,
                    event.target_entity_id,
                    event.correlation_id,
                    event.session_id,
                    event.parent_event_id,
                    event.content_hash,
                    event.importance_score,
                    event.importance_tier.value,
                    event.confidence,
                    event.model_dump_json(),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._extend_hash_chain(conn, event)
        logger.info("event_written", extra={"extra_fields": {"event_id": event.event_id}})
        return event

    def _extend_hash_chain(self, conn: sqlite3.Connection, event: CanonicalSecurityEvent) -> None:
        """Maintain a simple per-host hash chain so undetected tampering with
        historical events (outside of this API) becomes detectable."""
        if not event.host_id:
            return
        row = conn.execute(
            "SELECT last_hash, length FROM hash_chain WHERE host_id=?", (event.host_id,)
        ).fetchone()
        prev_hash = row["last_hash"] if row else "genesis"
        length = row["length"] if row else 0
        import hashlib

        chained = hashlib.sha256(f"{prev_hash}:{event.content_hash}".encode()).hexdigest()
        if row:
            conn.execute(
                "UPDATE hash_chain SET last_hash=?, length=? WHERE host_id=?",
                (chained, length + 1, event.host_id),
            )
        else:
            conn.execute(
                "INSERT INTO hash_chain (host_id, last_hash, length) VALUES (?,?,?)",
                (event.host_id, chained, 1),
            )

    def verify_hash_chain_length(self, host_id: str) -> Optional[int]:
        with self._tx() as conn:
            row = conn.execute("SELECT length FROM hash_chain WHERE host_id=?", (host_id,)).fetchone()
            return row["length"] if row else None

    def find_by_hash(self, content_hash: str) -> Optional[CanonicalSecurityEvent]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT body FROM normalized_events WHERE content_hash=?", (content_hash,)
            ).fetchone()
            return CanonicalSecurityEvent.model_validate_json(row["body"]) if row else None

    def get(self, event_id: str) -> Optional[CanonicalSecurityEvent]:
        with self._tx() as conn:
            row = conn.execute(
                "SELECT body FROM normalized_events WHERE event_id=?", (event_id,)
            ).fetchone()
            return CanonicalSecurityEvent.model_validate_json(row["body"]) if row else None

    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_category: Optional[str] = None,
        host_id: Optional[str] = None,
        entity_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        min_importance: Optional[float] = None,
        limit: int = 500,
    ) -> list[CanonicalSecurityEvent]:
        clauses, params = [], []
        if start_time:
            clauses.append("event_time >= ?")
            params.append(start_time.isoformat())
        if end_time:
            clauses.append("event_time <= ?")
            params.append(end_time.isoformat())
        if event_category:
            clauses.append("event_category = ?")
            params.append(event_category)
        if host_id:
            clauses.append("host_id = ?")
            params.append(host_id)
        if entity_id:
            clauses.append("(actor_entity_id = ? OR target_entity_id = ?)")
            params.extend([entity_id, entity_id])
        if correlation_id:
            clauses.append("correlation_id = ?")
            params.append(correlation_id)
        if min_importance is not None:
            clauses.append("importance_score >= ?")
            params.append(min_importance)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT body FROM normalized_events {where} ORDER BY event_time ASC LIMIT ?"
        params.append(limit)
        with self._tx() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [CanonicalSecurityEvent.model_validate_json(r["body"]) for r in rows]

    def count(self) -> int:
        with self._tx() as conn:
            return conn.execute("SELECT COUNT(*) c FROM normalized_events").fetchone()["c"]

    # ---- enrichment layer (append-only) ---------------------------------- #
    def add_enrichment(self, enrichment_id: str, event_id: str, enrichment_type: str, payload: dict) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO enrichments (enrichment_id, event_id, enrichment_type, payload, created_at) "
                "VALUES (?,?,?,?,?)",
                (enrichment_id, event_id, enrichment_type, json.dumps(payload, default=str),
                 datetime.now(timezone.utc).isoformat()),
            )

    def get_enrichments(self, event_id: str) -> list[dict]:
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT enrichment_type, payload, created_at FROM enrichments WHERE event_id=? "
                "ORDER BY created_at ASC",
                (event_id,),
            ).fetchall()
        return [
            {"type": r["enrichment_type"], "payload": json.loads(r["payload"]), "created_at": r["created_at"]}
            for r in rows
        ]

    # ---- derived layer (recomputable, references only) -------------------- #
    def write_derived(
        self, artifact_id: str, artifact_type: str, event_ids: Iterable[str], payload: dict, algorithm_version: str
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO derived_artifacts "
                "(artifact_id, artifact_type, event_ids, payload, algorithm_version, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (
                    artifact_id,
                    artifact_type,
                    json.dumps(list(event_ids)),
                    json.dumps(payload, default=str),
                    algorithm_version,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def get_derived(self, artifact_type: Optional[str] = None) -> list[dict]:
        with self._tx() as conn:
            if artifact_type:
                rows = conn.execute(
                    "SELECT * FROM derived_artifacts WHERE artifact_type=?", (artifact_type,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM derived_artifacts").fetchall()
        return [
            {
                "artifact_id": r["artifact_id"],
                "artifact_type": r["artifact_type"],
                "event_ids": json.loads(r["event_ids"]),
                "payload": json.loads(r["payload"]),
                "algorithm_version": r["algorithm_version"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def purge_derived(self, artifact_type: str) -> int:
        """Wipe a class of derived artifacts so it can be fully recomputed.
        Never touches normalized_events — this is what makes recomputation
        of correlation/causality/episodes/detections safe."""
        with self._tx() as conn:
            cur = conn.execute("DELETE FROM derived_artifacts WHERE artifact_type=?", (artifact_type,))
            return cur.rowcount
