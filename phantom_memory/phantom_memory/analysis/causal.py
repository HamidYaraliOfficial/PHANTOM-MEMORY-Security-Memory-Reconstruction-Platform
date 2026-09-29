"""
Causal Hypothesis Engine.

Keeps a hard line between correlation and causality. For every candidate
cause->effect event pair, this module classifies the *strength* of evidence
as one of:

  DIRECT      - an explicit mechanism links them (e.g. parent/child process,
                 an edge of type 'caused' or 'spawned' or 'triggered' with
                 direct provenance)
  TEMPORAL    - consistent, repeated temporal ordering (cause reliably
                 precedes effect) without a known mechanism
  STRUCTURAL  - graph connectivity between the entities involved, but no
                 temporal or mechanistic evidence
  SIMILARITY  - only that this pair resembles a pattern seen before

Causality is never asserted from timing coincidence alone: a hypothesis
built purely on "these two things happened close together" is always
labeled TEMPORAL (or SIMILARITY), never DIRECT, and its confidence is
capped accordingly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from phantom_memory.core.models import CanonicalSecurityEvent, CausalHypothesis, EdgeType, EvidenceStrength
from phantom_memory.graph.memory_graph import SecurityMemoryGraph
from phantom_memory.utils.ids import new_hypothesis_id

_DIRECT_EDGE_TYPES = {EdgeType.CAUSED, EdgeType.SPAWNED, EdgeType.TRIGGERED, EdgeType.EXECUTED}

_CONFIDENCE_CEILING = {
    EvidenceStrength.DIRECT: 0.95,
    EvidenceStrength.TEMPORAL: 0.65,
    EvidenceStrength.STRUCTURAL: 0.55,
    EvidenceStrength.SIMILARITY: 0.4,
}


@dataclass
class CausalEvidenceReport:
    direct_edges: list[str]
    structural_edges: list[str]
    temporal_gap_seconds: float
    repeated_pattern_count: int


class CausalHypothesisEngine:
    def __init__(self, memory_graph: SecurityMemoryGraph):
        self.mg = memory_graph

    def _gather_evidence(
        self, cause: CanonicalSecurityEvent, effect: CanonicalSecurityEvent
    ) -> CausalEvidenceReport:
        direct_edges, structural_edges = [], []
        cause_entities = set(cause.entity_ids)
        effect_entities = set(effect.entity_ids)

        for ent in cause_entities:
            for edge in self.mg.edges_for_entity(ent, direction="out"):
                if edge.target_entity_id in effect_entities:
                    if edge.edge_type in _DIRECT_EDGE_TYPES:
                        direct_edges.append(edge.edge_id)
                    else:
                        structural_edges.append(edge.edge_id)

        gap = (effect.timestamps.event_time - cause.timestamps.event_time).total_seconds()
        return CausalEvidenceReport(
            direct_edges=direct_edges,
            structural_edges=structural_edges,
            temporal_gap_seconds=gap,
            repeated_pattern_count=0,
        )

    def evaluate(
        self,
        cause: CanonicalSecurityEvent,
        effect: CanonicalSecurityEvent,
        *,
        historical_repetitions: int = 0,
        max_plausible_gap: timedelta = timedelta(hours=1),
    ) -> CausalHypothesis:
        evidence = self._gather_evidence(cause, effect)
        evidence.repeated_pattern_count = historical_repetitions

        contradicting: list[str] = []
        if evidence.temporal_gap_seconds < 0:
            contradicting.append(effect.event_id)  # effect precedes cause: contradicts hypothesis direction

        alternatives = []
        if evidence.repeated_pattern_count == 0 and not evidence.direct_edges:
            alternatives.append("Coincidental co-occurrence without a known mechanism.")
        if evidence.structural_edges and not evidence.direct_edges:
            alternatives.append("A shared upstream cause could explain both events independently.")

        if evidence.direct_edges and evidence.temporal_gap_seconds >= 0:
            strength = EvidenceStrength.DIRECT
            base_conf = 0.75 + min(0.2, 0.05 * len(evidence.direct_edges))
        elif (
            0 <= evidence.temporal_gap_seconds <= max_plausible_gap.total_seconds()
            and evidence.repeated_pattern_count >= 2
        ):
            strength = EvidenceStrength.TEMPORAL
            base_conf = 0.4 + min(0.2, 0.05 * evidence.repeated_pattern_count)
        elif evidence.structural_edges:
            strength = EvidenceStrength.STRUCTURAL
            base_conf = 0.35
        else:
            strength = EvidenceStrength.SIMILARITY
            base_conf = 0.2

        confidence = min(base_conf, _CONFIDENCE_CEILING[strength])
        if contradicting:
            confidence *= 0.3

        rationale_parts = [f"evidence_strength={strength.value}"]
        if evidence.direct_edges:
            rationale_parts.append(f"{len(evidence.direct_edges)} direct causal edge(s) in graph")
        if evidence.structural_edges:
            rationale_parts.append(f"{len(evidence.structural_edges)} structural edge(s) connect the entities")
        rationale_parts.append(f"temporal gap = {evidence.temporal_gap_seconds:.1f}s")
        if evidence.repeated_pattern_count:
            rationale_parts.append(f"pattern observed {evidence.repeated_pattern_count}x historically")

        return CausalHypothesis(
            hypothesis_id=new_hypothesis_id(),
            candidate_cause_event_id=cause.event_id,
            candidate_effect_event_id=effect.event_id,
            evidence_strength=strength,
            confidence=round(confidence, 4),
            supporting_event_ids=[cause.event_id, effect.event_id],
            contradicting_event_ids=contradicting,
            alternative_explanations=alternatives,
            rationale="; ".join(rationale_parts),
        )
