"""
Case Management System.

Cases move through Open -> Triage -> Investigating -> Validated ->
Contained -> Resolved -> Closed. Episodes, Evidence and Analysts attach to a
Case; every transition is recorded so the case's history is itself an
auditable timeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.utils.ids import new_case_id
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.cases")

ALGO_VERSION = "case-management-1.0.0"

_STATES = ["open", "triage", "investigating", "validated", "contained", "resolved", "closed"]
_TRANSITIONS = {
    "open": {"triage", "closed"},
    "triage": {"investigating", "closed"},
    "investigating": {"validated", "closed"},
    "validated": {"contained", "closed"},
    "contained": {"resolved", "closed"},
    "resolved": {"closed", "investigating"},  # reopen
    "closed": {"investigating"},  # reopen
}


class InvalidCaseTransitionError(Exception):
    pass


@dataclass
class CaseTransition:
    at: str
    from_state: str
    to_state: str
    actor: str
    note: str = ""


@dataclass
class Case:
    case_id: str
    title: str
    state: str = "open"
    episode_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    analysts: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    history: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    version: int = 1


class CaseManagementSystem:
    def __init__(self, store: EventStore):
        self.store = store

    def _persist(self, case: Case) -> None:
        self.store.write_derived(
            artifact_id=case.case_id,
            artifact_type="case",
            event_ids=[],
            payload=case.__dict__,
            algorithm_version=ALGO_VERSION,
        )

    def create(self, title: str, analyst: str, tags: Optional[list[str]] = None) -> Case:
        case = Case(case_id=new_case_id(), title=title, analysts=[analyst], tags=tags or [])
        self._persist(case)
        logger.info("case_created", extra={"extra_fields": {"case_id": case.case_id}})
        return case

    def get(self, case_id: str) -> Optional[Case]:
        for a in self.store.get_derived("case"):
            if a["artifact_id"] == case_id:
                p = a["payload"]
                return Case(**p)
        return None

    def list_cases(self, state: Optional[str] = None) -> list[Case]:
        cases = [Case(**a["payload"]) for a in self.store.get_derived("case")]
        if state:
            cases = [c for c in cases if c.state == state]
        return sorted(cases, key=lambda c: c.updated_at, reverse=True)

    def transition(self, case_id: str, new_state: str, actor: str, note: str = "") -> Case:
        case = self._require(case_id)
        allowed = _TRANSITIONS.get(case.state, set())
        if new_state not in allowed:
            raise InvalidCaseTransitionError(f"cannot move case from {case.state} to {new_state}")
        case.history.append({
            "at": datetime.now(timezone.utc).isoformat(), "from_state": case.state,
            "to_state": new_state, "actor": actor, "note": note,
        })
        case.state = new_state
        case.updated_at = datetime.now(timezone.utc).isoformat()
        case.version += 1
        self._persist(case)
        return case

    def attach_episode(self, case_id: str, episode_id: str) -> Case:
        case = self._require(case_id)
        if episode_id not in case.episode_ids:
            case.episode_ids.append(episode_id)
            case.updated_at = datetime.now(timezone.utc).isoformat()
            case.version += 1
            self._persist(case)
        return case

    def attach_evidence(self, case_id: str, evidence_id: str) -> Case:
        case = self._require(case_id)
        if evidence_id not in case.evidence_ids:
            case.evidence_ids.append(evidence_id)
            case.updated_at = datetime.now(timezone.utc).isoformat()
            case.version += 1
            self._persist(case)
        return case

    def add_analyst(self, case_id: str, analyst: str) -> Case:
        case = self._require(case_id)
        if analyst not in case.analysts:
            case.analysts.append(analyst)
            self._persist(case)
        return case

    def _require(self, case_id: str) -> Case:
        case = self.get(case_id)
        if case is None:
            raise KeyError(f"case {case_id} not found")
        return case
