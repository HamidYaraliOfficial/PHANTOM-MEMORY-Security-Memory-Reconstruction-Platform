"""
Entity Resolution Engine.

Resolves Process/User/Service/Container/Host/Identity/Network entities
observed by different sources into a single logical entity. Deterministic
natural-key matching (see `utils.ids.new_entity_id`) handles the easy cases
at ingestion time; this module handles the harder, similarity-based cases —
e.g. the same user identity reported as `jdoe` by one connector and
`jane.doe@corp` by another — and produces *reviewable, undoable* merges
rather than silent, permanent ones.
"""
from __future__ import annotations

from dataclasses import dataclass

from phantom_memory.graph.memory_graph import SecurityMemoryGraph
from phantom_memory.core.models import MemoryEntity


@dataclass
class MergeCandidate:
    entity_a: str
    entity_b: str
    score: float
    reasons: list[str]


class EntityResolutionEngine:
    def __init__(self, memory_graph: SecurityMemoryGraph):
        self.mg = memory_graph

    def _similarity(self, a: MemoryEntity, b: MemoryEntity) -> tuple[float, list[str]]:
        if a.entity_type != b.entity_type:
            return 0.0, []
        score = 0.0
        reasons = []

        name_a = (a.display_name or "").lower().strip()
        name_b = (b.display_name or "").lower().strip()
        if name_a and name_b:
            if name_a == name_b:
                score += 0.5
                reasons.append("identical display_name")
            elif name_a in name_b or name_b in name_a:
                score += 0.25
                reasons.append("display_name substring overlap")

        common_attr_keys = set(a.attributes) & set(b.attributes)
        matches = sum(1 for k in common_attr_keys if a.attributes[k] == b.attributes[k])
        if common_attr_keys:
            attr_score = 0.4 * (matches / len(common_attr_keys))
            score += attr_score
            if matches:
                reasons.append(f"{matches}/{len(common_attr_keys)} shared attributes match")

        # Temporal overlap: entities that co-existed are more plausibly the same
        overlap = not (a.last_seen < b.first_seen or b.last_seen < a.first_seen)
        if overlap:
            score += 0.1
            reasons.append("overlapping active time window")

        return min(score, 1.0), reasons

    def find_candidates(self, entity_ids: list[str], threshold: float = 0.6) -> list[MergeCandidate]:
        entities = [self.mg.get_entity(eid) for eid in entity_ids]
        entities = [e for e in entities if e is not None and e.merged_into is None]
        candidates: list[MergeCandidate] = []
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                score, reasons = self._similarity(entities[i], entities[j])
                if score >= threshold:
                    candidates.append(
                        MergeCandidate(
                            entity_a=entities[i].entity_id,
                            entity_b=entities[j].entity_id,
                            score=score,
                            reasons=reasons,
                        )
                    )
        return sorted(candidates, key=lambda c: c.score, reverse=True)

    def apply_merge(self, candidate: MergeCandidate, keep: str | None = None) -> str:
        keep_id = keep or candidate.entity_a
        drop_id = candidate.entity_b if keep_id == candidate.entity_a else candidate.entity_a
        self.mg.merge_entities(keep_id, drop_id, reason="; ".join(candidate.reasons) or "entity resolution")
        return keep_id

    def undo_merge(self, dropped_entity_id: str) -> None:
        self.mg.undo_merge(dropped_entity_id)
