"""
Snapshot Engine.

Creates named, timestamped snapshots of graph state, temporal system state,
and (optionally) memory-index/detection-worker health, so that Replay can
jump near a target time instead of always replaying from the very first
event, and so Diff can compare two points in the system's history.

Snapshots are stored as derived artifacts (never touching normalized
events), fully recomputable from raw event history if ever discarded.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.temporal.memory_engine import SystemStateAtTime, TemporalMemoryEngine
from phantom_memory.utils.ids import new_snapshot_id

ALGO_VERSION = "snapshot-engine-1.0.0"


@dataclass
class Snapshot:
    snapshot_id: str
    at_time: str
    created_at: str
    state: dict
    node_count: int
    edge_count: int
    label: Optional[str] = None


class SnapshotEngine:
    def __init__(self, event_store: EventStore, temporal_engine: TemporalMemoryEngine):
        self.store = event_store
        self.temporal = temporal_engine

    def create_snapshot(self, at_time: datetime, label: Optional[str] = None) -> Snapshot:
        state: SystemStateAtTime = self.temporal.state_at(at_time)
        snap = Snapshot(
            snapshot_id=new_snapshot_id(),
            at_time=at_time.isoformat(),
            created_at=datetime.now(timezone.utc).isoformat(),
            state=asdict(state),
            node_count=self.temporal.mg.node_count(),
            edge_count=self.temporal.mg.edge_count(),
            label=label,
        )
        self.store.write_derived(
            artifact_id=snap.snapshot_id,
            artifact_type="snapshot",
            event_ids=[],
            payload=asdict(snap),
            algorithm_version=ALGO_VERSION,
        )
        return snap

    def list_snapshots(self) -> list[dict]:
        return sorted(self.store.get_derived("snapshot"), key=lambda x: x["payload"]["at_time"])

    def get_snapshot(self, snapshot_id: str) -> Optional[dict]:
        for artifact in self.store.get_derived("snapshot"):
            if artifact["artifact_id"] == snapshot_id:
                return artifact
        return None

    def nearest_snapshot(self, at_time: datetime) -> Optional[dict]:
        """Latest snapshot at or before `at_time`, used by Replay to skip ahead."""
        candidates = [
            s for s in self.list_snapshots() if s["payload"]["at_time"] <= at_time.isoformat()
        ]
        return candidates[-1] if candidates else None
