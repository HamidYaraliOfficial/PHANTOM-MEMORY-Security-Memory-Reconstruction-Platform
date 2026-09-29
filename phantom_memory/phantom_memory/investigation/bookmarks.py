"""
Evidence Bookmark System.

Lets an analyst bookmark an Event, Edge, Time Range, Snapshot, or Episode
and attach an annotation to it — the smallest unit of "I looked at this and
it matters" in an investigation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.utils.ids import new_bookmark_id

ALGO_VERSION = "evidence-bookmarks-1.0.0"

_VALID_SUBJECT_TYPES = {"event", "edge", "time_range", "snapshot", "episode"}


@dataclass
class Bookmark:
    bookmark_id: str
    subject_type: str
    subject_ref: str
    case_id: Optional[str]
    annotation: str
    analyst: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EvidenceBookmarkSystem:
    def __init__(self, store: EventStore):
        self.store = store

    def create(
        self, subject_type: str, subject_ref: str, annotation: str, analyst: str, case_id: Optional[str] = None
    ) -> Bookmark:
        if subject_type not in _VALID_SUBJECT_TYPES:
            raise ValueError(f"invalid subject_type '{subject_type}', must be one of {_VALID_SUBJECT_TYPES}")
        bookmark = Bookmark(
            bookmark_id=new_bookmark_id(),
            subject_type=subject_type,
            subject_ref=subject_ref,
            case_id=case_id,
            annotation=annotation,
            analyst=analyst,
        )
        self.store.write_derived(
            artifact_id=bookmark.bookmark_id,
            artifact_type="bookmark",
            event_ids=[subject_ref] if subject_type == "event" else [],
            payload=bookmark.__dict__,
            algorithm_version=ALGO_VERSION,
        )
        return bookmark

    def list_for_case(self, case_id: str) -> list[Bookmark]:
        return [
            Bookmark(**a["payload"]) for a in self.store.get_derived("bookmark")
            if a["payload"].get("case_id") == case_id
        ]

    def list_all(self) -> list[Bookmark]:
        return [Bookmark(**a["payload"]) for a in self.store.get_derived("bookmark")]
