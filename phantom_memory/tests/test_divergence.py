from __future__ import annotations

from datetime import timedelta

from phantom_memory.analysis.divergence import BehavioralBaseline, FirstDivergenceEngine
from phantom_memory.core.models import EventCategory

from .conftest import make_event


def test_first_unexpected_process_detected(base_time):
    baseline_events = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time + timedelta(seconds=i), payload={"process_name": "bash"},
        )
        for i in range(3)
    ]
    baseline = BehavioralBaseline.from_events(baseline_events)

    incident_events = baseline_events + [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_c",
            base_time + timedelta(seconds=30), payload={"process_name": "mystery_binary"},
        )
    ]

    engine = FirstDivergenceEngine()
    findings = engine.find(incident_events, baseline)
    assert findings["first_unexpected_process"] is not None
    assert "mystery_binary" in findings["first_unexpected_process"].description


def test_no_divergence_when_all_known(base_time):
    events = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time + timedelta(seconds=i), payload={"process_name": "bash"},
        )
        for i in range(3)
    ]
    baseline = BehavioralBaseline.from_events(events)
    engine = FirstDivergenceEngine()
    findings = engine.find(events, baseline)
    assert findings["first_unexpected_process"] is None


def test_overall_first_divergence_picks_earliest(base_time):
    baseline = BehavioralBaseline()
    events = [
        make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time + timedelta(seconds=10), payload={"process_name": "new_proc"},
        ),
        make_event(
            "network.connect", EventCategory.NETWORK_CONNECTION, "ent_a", "ent_c",
            base_time + timedelta(seconds=5),
            payload={"source_endpoint": "10.0.0.1", "destination_endpoint": "1.2.3.4"},
        ),
    ]
    engine = FirstDivergenceEngine()
    findings = engine.find(events, baseline)
    overall = engine.overall_first_divergence(findings)
    assert overall is not None
    assert overall.kind == "first_new_connection"
