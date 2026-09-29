from __future__ import annotations

from datetime import timedelta

from phantom_memory.core.models import EventCategory
from phantom_memory.retrieval.similarity import HistoricalSimilarityEngine, IncidentFingerprint

from .conftest import make_event


def test_identical_fingerprints_score_high(base_time):
    events_a = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time + timedelta(seconds=i), payload={"process_name": "curl"},
        )
        for i in range(3)
    ]
    events_b = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_x", "ent_y",
            base_time + timedelta(days=10, seconds=i), payload={"process_name": "curl"},
        )
        for i in range(3)
    ]
    fp_a = IncidentFingerprint.from_events("inc_a", events_a)
    fp_b = IncidentFingerprint.from_events("inc_b", events_b)

    engine = HistoricalSimilarityEngine()
    result = engine.compare(fp_a, fp_b)
    assert result.process_pattern_similarity == 1.0
    assert result.overall > 0.5


def test_dissimilar_fingerprints_score_low(base_time):
    events_a = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time, payload={"process_name": "curl"},
        )
    ]
    events_b = [
        make_event(
            "authentication.login", EventCategory.AUTHENTICATION, "ent_x", "ent_y",
            base_time + timedelta(days=5),
        )
    ]
    fp_a = IncidentFingerprint.from_events("inc_a", events_a)
    fp_b = IncidentFingerprint.from_events("inc_b", events_b)

    engine = HistoricalSimilarityEngine()
    result = engine.compare(fp_a, fp_b)
    assert result.overall < 0.5
