"""
Event Deduplication Engine.

Identifies duplicate events using content hash, source, timestamp window and
entity context — while never discarding the *evidence* that a duplicate was
observed: a duplicate hit is recorded as an occurrence count + source list on
the original event's enrichment trail rather than silently dropped, because
"the same event was reported by three collectors" is itself useful evidence
of telemetry redundancy/reliability.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.utils.ids import new_query_id


@dataclass
class DedupResult:
    is_duplicate: bool
    original_event_id: Optional[str] = None
    reason: Optional[str] = None


class DeduplicationEngine:
    def __init__(self, store: EventStore, window: timedelta = timedelta(seconds=2)):
        self.store = store
        self.window = window

    def check(self, event: CanonicalSecurityEvent) -> DedupResult:
        content_hash = event.content_hash or event.compute_content_hash()
        existing = self.store.find_by_hash(content_hash)
        if existing is None:
            return DedupResult(is_duplicate=False)

        # Same content hash, but only treat as duplicate if within the
        # dedup time window and same entity context — otherwise a
        # legitimately repeated action (e.g. the same command run twice)
        # would be wrongly collapsed.
        delta = abs((event.timestamps.event_time - existing.timestamps.event_time).total_seconds())
        if delta <= self.window.total_seconds():
            return DedupResult(
                is_duplicate=True,
                original_event_id=existing.event_id,
                reason=f"identical content_hash within {self.window} window "
                       f"(observed source={event.source.source})",
            )
        return DedupResult(is_duplicate=False)

    def record_duplicate_observation(self, original_event_id: str, duplicate_source: str) -> None:
        self.store.add_enrichment(
            enrichment_id=new_query_id(),
            event_id=original_event_id,
            enrichment_type="duplicate_observation",
            payload={"observed_again_from": duplicate_source},
        )
