from __future__ import annotations

from datetime import timedelta

from phantom_memory.analysis.causal import CausalHypothesisEngine
from phantom_memory.core.models import EdgeType, EntityType, EventCategory, EvidenceStrength

from .conftest import make_event


def test_direct_edge_yields_direct_evidence(system, base_time):
    system.graph.upsert_entity(EntityType.PROCESS, "a", natural_key="ent_a", at_time=base_time)
    system.graph.upsert_entity(EntityType.PROCESS, "b", natural_key="ent_b", at_time=base_time)
    system.graph.add_edge(
        EdgeType.SPAWNED, "ent_a", "ent_b", valid_from=base_time, confidence=0.9,
    )
    cause = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_x", base_time)
    effect = make_event(
        "process.exec", EventCategory.PROCESS, "ent_b", "ent_y", base_time + timedelta(seconds=1)
    )
    # Manually align entity_ids so the graph edge is discoverable
    cause.entity_ids = ["ent_a"]
    effect.entity_ids = ["ent_b"]

    engine = CausalHypothesisEngine(system.graph)
    hyp = engine.evaluate(cause, effect)
    assert hyp.evidence_strength == EvidenceStrength.DIRECT
    assert hyp.confidence > 0.5


def test_no_evidence_yields_similarity_strength(system, base_time):
    cause = make_event("process.exec", EventCategory.PROCESS, "ent_z1", "ent_z2", base_time)
    effect = make_event(
        "process.exec", EventCategory.PROCESS, "ent_z3", "ent_z4", base_time + timedelta(seconds=1)
    )
    engine = CausalHypothesisEngine(system.graph)
    hyp = engine.evaluate(cause, effect)
    assert hyp.evidence_strength == EvidenceStrength.SIMILARITY
    assert hyp.confidence <= 0.4


def test_effect_before_cause_is_contradicting(system, base_time):
    cause = make_event("process.exec", EventCategory.PROCESS, "ent_p", "ent_q", base_time)
    effect = make_event(
        "process.exec", EventCategory.PROCESS, "ent_r", "ent_s", base_time - timedelta(seconds=5)
    )
    engine = CausalHypothesisEngine(system.graph)
    hyp = engine.evaluate(cause, effect)
    assert effect.event_id in hyp.contradicting_event_ids
