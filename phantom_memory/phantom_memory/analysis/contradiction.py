"""
Contradiction Detector.

When two sources report inconsistent information about the same event or
relationship — different actor, different outcome, conflicting timestamps
beyond tolerance — this module records an Evidence Conflict rather than
silently picking a winner. Conflicts are surfaced to the Memory Confidence
Engine and to analysts; no derived conclusion may be marked as resolved
until the conflict is explicitly addressed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from phantom_memory.core.models import CanonicalSecurityEvent, MemoryEdge


@dataclass
class EvidenceConflict:
    conflict_id: str
    subject: str  # event_id or edge_id the conflict is about
    field_name: str
    source_a: str
    value_a: str
    source_b: str
    value_b: str
    severity: str  # 'low' | 'medium' | 'high'
    resolved: bool = False
    resolution_notes: str = ""


class ContradictionDetector:
    def __init__(self, timestamp_tolerance: timedelta = timedelta(seconds=5)):
        self.timestamp_tolerance = timestamp_tolerance
        self._conflicts: list[EvidenceConflict] = []

    def compare_events(self, a: CanonicalSecurityEvent, b: CanonicalSecurityEvent) -> list[EvidenceConflict]:
        """Compare two events that different sources reported as 'the same
        thing' (same content_hash or explicitly linked) for field-level
        disagreement."""
        conflicts: list[EvidenceConflict] = []
        if a.actor_entity_id and b.actor_entity_id and a.actor_entity_id != b.actor_entity_id:
            conflicts.append(self._new(a.event_id, "actor_entity_id", a, b, "high"))
        if a.target_entity_id and b.target_entity_id and a.target_entity_id != b.target_entity_id:
            conflicts.append(self._new(a.event_id, "target_entity_id", a, b, "high"))

        delta = abs((a.timestamps.event_time - b.timestamps.event_time).total_seconds())
        if delta > self.timestamp_tolerance.total_seconds():
            conflicts.append(self._new(a.event_id, "event_time", a, b, "medium"))

        if (
            a.classification.classification != b.classification.classification
            and a.classification.classification.value != "unknown"
            and b.classification.classification.value != "unknown"
        ):
            conflicts.append(self._new(a.event_id, "classification", a, b, "medium"))

        self._conflicts.extend(conflicts)
        return conflicts

    def compare_edges(self, a: MemoryEdge, b: MemoryEdge) -> list[EvidenceConflict]:
        conflicts: list[EvidenceConflict] = []
        if a.edge_type != b.edge_type:
            conflicts.append(
                EvidenceConflict(
                    conflict_id=f"conf_{a.edge_id}_{b.edge_id}",
                    subject=f"{a.source_entity_id}->{a.target_entity_id}",
                    field_name="edge_type",
                    source_a=a.edge_id,
                    value_a=a.edge_type.value,
                    source_b=b.edge_id,
                    value_b=b.edge_type.value,
                    severity="high",
                )
            )
        self._conflicts.extend(conflicts)
        return conflicts

    def _new(self, subject: str, field_name: str, a: CanonicalSecurityEvent, b: CanonicalSecurityEvent, severity: str) -> EvidenceConflict:
        return EvidenceConflict(
            conflict_id=f"conf_{a.event_id}_{b.event_id}_{field_name}",
            subject=subject,
            field_name=field_name,
            source_a=a.source.source.value,
            value_a=str(getattr(a, field_name, None) or a.timestamps.event_time),
            source_b=b.source.source.value,
            value_b=str(getattr(b, field_name, None) or b.timestamps.event_time),
            severity=severity,
        )

    def resolve(self, conflict_id: str, notes: str) -> bool:
        for c in self._conflicts:
            if c.conflict_id == conflict_id:
                c.resolved = True
                c.resolution_notes = notes
                return True
        return False

    def unresolved(self) -> list[EvidenceConflict]:
        return [c for c in self._conflicts if not c.resolved]

    def all(self) -> list[EvidenceConflict]:
        return list(self._conflicts)
