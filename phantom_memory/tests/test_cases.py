from __future__ import annotations

import pytest

from phantom_memory.investigation.cases import CaseManagementSystem, InvalidCaseTransitionError


def test_case_lifecycle_happy_path(system):
    mgr = CaseManagementSystem(system.store)
    case = mgr.create("Suspicious login burst", analyst="alice")
    assert case.state == "open"

    case = mgr.transition(case.case_id, "triage", actor="alice")
    case = mgr.transition(case.case_id, "investigating", actor="alice")
    case = mgr.transition(case.case_id, "validated", actor="bob")
    case = mgr.transition(case.case_id, "contained", actor="bob")
    case = mgr.transition(case.case_id, "resolved", actor="bob")
    case = mgr.transition(case.case_id, "closed", actor="bob")
    assert case.state == "closed"
    assert len(case.history) == 6


def test_invalid_transition_rejected(system):
    mgr = CaseManagementSystem(system.store)
    case = mgr.create("Test", analyst="alice")
    with pytest.raises(InvalidCaseTransitionError):
        mgr.transition(case.case_id, "resolved", actor="alice")  # can't skip straight to resolved


def test_attach_episode_and_evidence(system):
    mgr = CaseManagementSystem(system.store)
    case = mgr.create("Test", analyst="alice")
    mgr.attach_episode(case.case_id, "epi_123")
    mgr.attach_evidence(case.case_id, "evt_456")
    case = mgr.get(case.case_id)
    assert "epi_123" in case.episode_ids
    assert "evt_456" in case.evidence_ids
