"""
Event Replay Engine.

Re-executes the immutable event history through a pluggable `on_event`
callback (typically the ingestion/reconstruction pipeline) so that Graph
state, Episodes and derived artifacts can be rebuilt deterministically from
scratch. Supports pause, resume, step-by-step, fast-forward (N events),
time-jump (via the nearest Snapshot), event/entity filtering, and
cooperative cancellation.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.temporal.snapshot import SnapshotEngine


class ReplayStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class ReplayProgress:
    status: ReplayStatus = ReplayStatus.IDLE
    cursor_index: int = 0
    total_events: int = 0
    last_event_id: Optional[str] = None
    last_event_time: Optional[str] = None
    started_from_snapshot: Optional[str] = None
    processed_count: int = 0


OnEventCallback = Callable[[CanonicalSecurityEvent], None]


class ReplayEngine:
    def __init__(self, store: EventStore, snapshot_engine: Optional[SnapshotEngine] = None):
        self.store = store
        self.snapshots = snapshot_engine
        self._events: list[CanonicalSecurityEvent] = []
        self._progress = ReplayProgress()
        self._lock = threading.RLock()
        self._pause_flag = threading.Event()
        self._cancel_flag = threading.Event()

    def load(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        host_id: Optional[str] = None,
        entity_id: Optional[str] = None,
        use_nearest_snapshot: bool = True,
    ) -> ReplayProgress:
        with self._lock:
            snap_used = None
            effective_start = start_time
            if use_nearest_snapshot and self.snapshots and start_time:
                nearest = self.snapshots.nearest_snapshot(start_time)
                if nearest:
                    snap_used = nearest["artifact_id"]
                    effective_start = datetime.fromisoformat(nearest["payload"]["at_time"])

            self._events = self.store.query(
                start_time=effective_start,
                end_time=end_time,
                host_id=host_id,
                entity_id=entity_id,
                limit=10_000_000,
            )
            self._progress = ReplayProgress(
                status=ReplayStatus.IDLE,
                cursor_index=0,
                total_events=len(self._events),
                started_from_snapshot=snap_used,
            )
            self._pause_flag.clear()
            self._cancel_flag.clear()
            return self._progress

    def pause(self) -> None:
        self._pause_flag.set()
        self._progress.status = ReplayStatus.PAUSED

    def resume(self) -> None:
        self._pause_flag.clear()
        if self._progress.status == ReplayStatus.PAUSED:
            self._progress.status = ReplayStatus.RUNNING

    def cancel(self) -> None:
        self._cancel_flag.set()
        self._progress.status = ReplayStatus.CANCELLED

    def step(self, on_event: OnEventCallback) -> Optional[CanonicalSecurityEvent]:
        """Advance exactly one event and apply the callback."""
        with self._lock:
            if self._progress.cursor_index >= len(self._events):
                self._progress.status = ReplayStatus.COMPLETED
                return None
            event = self._events[self._progress.cursor_index]
            on_event(event)
            self._progress.cursor_index += 1
            self._progress.processed_count += 1
            self._progress.last_event_id = event.event_id
            self._progress.last_event_time = event.timestamps.event_time.isoformat()
            if self._progress.cursor_index >= len(self._events):
                self._progress.status = ReplayStatus.COMPLETED
            return event

    def play(self, on_event: OnEventCallback, max_events: Optional[int] = None) -> ReplayProgress:
        """Fast-forward: process events until max_events reached, paused, or cancelled."""
        self._progress.status = ReplayStatus.RUNNING
        count = 0
        while True:
            if self._cancel_flag.is_set():
                self._progress.status = ReplayStatus.CANCELLED
                break
            if self._pause_flag.is_set():
                self._progress.status = ReplayStatus.PAUSED
                break
            event = self.step(on_event)
            if event is None:
                break
            count += 1
            if max_events is not None and count >= max_events:
                if self._progress.status != ReplayStatus.COMPLETED:
                    self._progress.status = ReplayStatus.PAUSED
                break
        return self._progress

    def jump_to_time(self, target_time: datetime) -> int:
        """Move the cursor to the first loaded event at/after target_time
        without invoking callbacks (used for scrubbing the timeline UI)."""
        with self._lock:
            for i, event in enumerate(self._events):
                if event.timestamps.event_time >= target_time:
                    self._progress.cursor_index = i
                    return i
            self._progress.cursor_index = len(self._events)
            return len(self._events)

    @property
    def progress(self) -> ReplayProgress:
        return self._progress
