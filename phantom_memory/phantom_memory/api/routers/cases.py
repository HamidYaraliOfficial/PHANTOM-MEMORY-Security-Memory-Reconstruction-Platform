"""
/api/v1/cases — case management workflow.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from phantom_memory.api.deps import get_system
from phantom_memory.investigation.cases import InvalidCaseTransitionError
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])


class CreateCaseRequest(BaseModel):
    title: str
    analyst: str
    tags: list[str] = []


@router.post("", status_code=201)
def create_case(req: CreateCaseRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.cases.create(req.title, req.analyst, req.tags).__dict__


@router.get("")
def list_cases(state: Optional[str] = None, system: PhantomMemorySystem = Depends(get_system)):
    return {"cases": [c.__dict__ for c in system.cases.list_cases(state)]}


@router.get("/{case_id}")
def get_case(case_id: str, system: PhantomMemorySystem = Depends(get_system)):
    case = system.cases.get(case_id)
    if case is None:
        raise HTTPException(404, f"case {case_id} not found")
    return case.__dict__


class TransitionRequest(BaseModel):
    new_state: str
    actor: str
    note: str = ""


@router.post("/{case_id}/transition")
def transition_case(case_id: str, req: TransitionRequest, system: PhantomMemorySystem = Depends(get_system)):
    try:
        return system.cases.transition(case_id, req.new_state, req.actor, req.note).__dict__
    except InvalidCaseTransitionError as exc:
        raise HTTPException(400, str(exc))


@router.post("/{case_id}/episodes/{episode_id}")
def attach_episode(case_id: str, episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    return system.cases.attach_episode(case_id, episode_id).__dict__


@router.post("/{case_id}/evidence/{evidence_id}")
def attach_evidence(case_id: str, evidence_id: str, system: PhantomMemorySystem = Depends(get_system)):
    return system.cases.attach_evidence(case_id, evidence_id).__dict__
