"""
Security Memory Graph.

Nodes: Process, User, Service, Host, Container, Network Endpoint, File,
API, Database, Identity, Configuration, Deployment, Event, Incident,
Episode, Security Control.

Edges: caused, preceded_by, followed_by, spawned, connected_to,
authenticated_to, accessed, modified, executed, depends_on, belongs_to,
triggered, observed_on, related_to, part_of_episode.

Every edge is temporal (valid_from/valid_to), versioned, and carries a
confidence score plus the event IDs that constitute its evidence. Nothing
in this module ever deletes an edge outright — superseding an edge creates
a new version and points `superseded_by` at it, so "what did we believe
connected these two entities as of time T" stays answerable.

Backed by SQLite for persistence and NetworkX in-memory for traversal —
this keeps the implementation adapter-friendly: swapping to Neo4j/JanusGraph
later means reimplementing this module's public interface, not touching
callers.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

import networkx as nx

from phantom_memory.core.models import EdgeType, EntityType, EvidenceStrength, MemoryEdge, MemoryEntity
from phantom_memory.utils.ids import new_entity_id
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.graph")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    entity_id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    display_name TEXT NOT NULL,
    natural_key TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    attributes TEXT NOT NULL,
    criticality REAL DEFAULT 0.3,
    merged_into TEXT,
    version INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_entity_natural_key ON entities(natural_key);
CREATE INDEX IF NOT EXISTS idx_entity_type ON entities(entity_type);

CREATE TABLE IF NOT EXISTS edges (
    edge_id TEXT PRIMARY KEY,
    edge_type TEXT NOT NULL,
    source_entity_id TEXT NOT NULL,
    target_entity_id TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    confidence REAL DEFAULT 0.5,
    evidence_strength TEXT DEFAULT 'temporal',
    evidence_event_ids TEXT NOT NULL,
    supporting_notes TEXT,
    version INTEGER DEFAULT 1,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_edge_source ON edges(source_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_target ON edges(target_entity_id);
CREATE INDEX IF NOT EXISTS idx_edge_valid_from ON edges(valid_from);
CREATE INDEX IF NOT EXISTS idx_edge_type ON edges(edge_type);
"""


class SecurityMemoryGraph:
    def __init__(self, db_path: str | Path = "data/phantom_graph.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._local = threading.local()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
        # In-memory traversal graph, rebuilt lazily / kept in sync on writes.
        self._g = nx.MultiDiGraph()
        self._load_into_memory()

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

    def _load_into_memory(self) -> None:
        with self._tx() as conn:
            for row in conn.execute("SELECT * FROM entities"):
                self._g.add_node(row["entity_id"], **dict(row))
            for row in conn.execute("SELECT * FROM edges WHERE superseded_by IS NULL"):
                self._g.add_edge(
                    row["source_entity_id"], row["target_entity_id"], key=row["edge_id"], **dict(row)
                )

    # ---- entities ------------------------------------------------------- #
    def upsert_entity(
        self,
        entity_type: EntityType,
        display_name: str,
        *,
        natural_key: Optional[str] = None,
        at_time: Optional[datetime] = None,
        attributes: Optional[dict] = None,
        criticality: float = 0.3,
    ) -> MemoryEntity:
        at_time = at_time or datetime.now(timezone.utc)
        attributes = attributes or {}
        with self._tx() as conn:
            existing = None
            if natural_key:
                existing = conn.execute(
                    "SELECT * FROM entities WHERE natural_key=? AND merged_into IS NULL", (natural_key,)
                ).fetchone()
            if existing:
                new_last_seen = max(existing["last_seen"], at_time.isoformat())
                merged_attrs = {**json.loads(existing["attributes"]), **attributes}
                conn.execute(
                    "UPDATE entities SET last_seen=?, attributes=?, version=version+1 WHERE entity_id=?",
                    (new_last_seen, json.dumps(merged_attrs, default=str), existing["entity_id"]),
                )
                entity = MemoryEntity(
                    entity_id=existing["entity_id"],
                    entity_type=EntityType(existing["entity_type"]),
                    display_name=existing["display_name"],
                    natural_key=natural_key,
                    first_seen=datetime.fromisoformat(existing["first_seen"]),
                    last_seen=datetime.fromisoformat(new_last_seen),
                    attributes=merged_attrs,
                    criticality=existing["criticality"],
                    version=existing["version"] + 1,
                )
            else:
                entity_id = new_entity_id(entity_type.value, natural_key)
                conn.execute(
                    "INSERT INTO entities (entity_id, entity_type, display_name, natural_key, "
                    "first_seen, last_seen, attributes, criticality, version) VALUES (?,?,?,?,?,?,?,?,1)",
                    (
                        entity_id,
                        entity_type.value,
                        display_name,
                        natural_key,
                        at_time.isoformat(),
                        at_time.isoformat(),
                        json.dumps(attributes, default=str),
                        criticality,
                    ),
                )
                entity = MemoryEntity(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    display_name=display_name,
                    natural_key=natural_key,
                    first_seen=at_time,
                    last_seen=at_time,
                    attributes=attributes,
                    criticality=criticality,
                )
        self._g.add_node(entity.entity_id, entity_type=entity.entity_type.value, display_name=display_name)
        return entity

    def get_entity(self, entity_id: str) -> Optional[MemoryEntity]:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM entities WHERE entity_id=?", (entity_id,)).fetchone()
        if not row:
            return None
        return MemoryEntity(
            entity_id=row["entity_id"],
            entity_type=EntityType(row["entity_type"]),
            display_name=row["display_name"],
            natural_key=row["natural_key"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            attributes=json.loads(row["attributes"]),
            criticality=row["criticality"],
            merged_into=row["merged_into"],
            version=row["version"],
        )

    def merge_entities(self, keep_entity_id: str, merge_entity_id: str, reason: str) -> None:
        """Entity Resolution merge: `merge_entity_id` is marked as merged into
        `keep_entity_id`. Reviewable/undoable because `merged_into` is just a
        pointer, never a delete."""
        with self._tx() as conn:
            conn.execute(
                "UPDATE entities SET merged_into=?, version=version+1 WHERE entity_id=?",
                (keep_entity_id, merge_entity_id),
            )
            conn.execute(
                "UPDATE edges SET source_entity_id=? WHERE source_entity_id=?",
                (keep_entity_id, merge_entity_id),
            )
            conn.execute(
                "UPDATE edges SET target_entity_id=? WHERE target_entity_id=?",
                (keep_entity_id, merge_entity_id),
            )
        logger.info("entity_merged", extra={"extra_fields": {
            "kept": keep_entity_id, "merged": merge_entity_id, "reason": reason
        }})

    def undo_merge(self, merge_entity_id: str) -> None:
        with self._tx() as conn:
            conn.execute("UPDATE entities SET merged_into=NULL WHERE entity_id=?", (merge_entity_id,))

    # ---- edges ------------------------------------------------------------ #
    def add_edge(
        self,
        edge_type: EdgeType,
        source_entity_id: str,
        target_entity_id: str,
        *,
        valid_from: datetime,
        valid_to: Optional[datetime] = None,
        confidence: float = 0.5,
        evidence_strength: EvidenceStrength = EvidenceStrength.TEMPORAL,
        evidence_event_ids: Optional[list[str]] = None,
        supporting_notes: Optional[str] = None,
    ) -> MemoryEdge:
        from phantom_memory.utils.ids import new_correlation_id

        edge_id = f"edge_{new_correlation_id()}"
        evidence_event_ids = evidence_event_ids or []
        edge = MemoryEdge(
            edge_id=edge_id,
            edge_type=edge_type,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            valid_from=valid_from,
            valid_to=valid_to,
            confidence=confidence,
            evidence_strength=evidence_strength,
            evidence_event_ids=evidence_event_ids,
            supporting_notes=supporting_notes,
        )
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO edges (edge_id, edge_type, source_entity_id, target_entity_id, valid_from, "
                "valid_to, confidence, evidence_strength, evidence_event_ids, supporting_notes, version) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,1)",
                (
                    edge.edge_id,
                    edge.edge_type.value,
                    source_entity_id,
                    target_entity_id,
                    valid_from.isoformat(),
                    valid_to.isoformat() if valid_to else None,
                    confidence,
                    evidence_strength.value,
                    json.dumps(evidence_event_ids),
                    supporting_notes,
                ),
            )
        self._g.add_edge(
            source_entity_id, target_entity_id, key=edge_id,
            edge_type=edge_type.value, valid_from=valid_from.isoformat(),
            confidence=confidence, evidence_strength=evidence_strength.value,
        )
        return edge

    def supersede_edge(self, old_edge_id: str, new_edge: MemoryEdge) -> None:
        with self._tx() as conn:
            conn.execute("UPDATE edges SET superseded_by=? WHERE edge_id=?", (new_edge.edge_id, old_edge_id))

    def edges_for_entity(
        self, entity_id: str, at_time: Optional[datetime] = None, direction: str = "both"
    ) -> list[MemoryEdge]:
        clauses = ["superseded_by IS NULL"]
        params: list = []
        if direction in ("out", "both"):
            src_clause = "source_entity_id=?"
        if direction == "out":
            clauses.append("source_entity_id=?")
            params.append(entity_id)
        elif direction == "in":
            clauses.append("target_entity_id=?")
            params.append(entity_id)
        else:
            clauses.append("(source_entity_id=? OR target_entity_id=?)")
            params.extend([entity_id, entity_id])
        if at_time:
            clauses.append("valid_from <= ?")
            params.append(at_time.isoformat())
            clauses.append("(valid_to IS NULL OR valid_to >= ?)")
            params.append(at_time.isoformat())
        sql = f"SELECT * FROM edges WHERE {' AND '.join(clauses)} ORDER BY valid_from ASC"
        with self._tx() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def _row_to_edge(self, row: sqlite3.Row) -> MemoryEdge:
        return MemoryEdge(
            edge_id=row["edge_id"],
            edge_type=EdgeType(row["edge_type"]),
            source_entity_id=row["source_entity_id"],
            target_entity_id=row["target_entity_id"],
            valid_from=datetime.fromisoformat(row["valid_from"]),
            valid_to=datetime.fromisoformat(row["valid_to"]) if row["valid_to"] else None,
            confidence=row["confidence"],
            evidence_strength=EvidenceStrength(row["evidence_strength"]),
            evidence_event_ids=json.loads(row["evidence_event_ids"]),
            supporting_notes=row["supporting_notes"],
            version=row["version"],
            superseded_by=row["superseded_by"],
        )

    def edges_valid_at(
        self, at_time: datetime, edge_type: Optional[EdgeType] = None, limit: int = 5000
    ) -> list[MemoryEdge]:
        """Graph-wide lookup of every edge that was valid at a given instant.
        This is the primitive the Temporal Memory Engine uses to answer
        'what was true about the system at time T'."""
        clauses = ["superseded_by IS NULL", "valid_from <= ?", "(valid_to IS NULL OR valid_to >= ?)"]
        params: list = [at_time.isoformat(), at_time.isoformat()]
        if edge_type:
            clauses.append("edge_type = ?")
            params.append(edge_type.value)
        sql = f"SELECT * FROM edges WHERE {' AND '.join(clauses)} ORDER BY valid_from ASC LIMIT ?"
        params.append(limit)
        with self._tx() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_edge(r) for r in rows]

    def node_count(self) -> int:
        return self._g.number_of_nodes()

    def edge_count(self) -> int:
        return self._g.number_of_edges()

    @property
    def graph(self) -> nx.MultiDiGraph:
        return self._g
