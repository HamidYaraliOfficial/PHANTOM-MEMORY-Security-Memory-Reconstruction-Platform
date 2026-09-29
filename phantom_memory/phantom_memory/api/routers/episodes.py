"""
/api/v1/episodes — reconstruction, lifecycle transitions, and analysis.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from phantom_memory.api.deps import get_system
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/episodes", tags=["episodes"])


class ReconstructRequest(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


@router.post("/reconstruct")
def reconstruct(req: ReconstructRequest, system: PhantomMemorySystem = Depends(get_system)):
    episodes = system.reconstruct_episodes(req.start_time, req.end_time)
    return {"count": len(episodes), "episodes": [e.model_dump(mode="json") for e in episodes]}


@router.get("")
def list_episodes(
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    entity_id: Optional[str] = None, system: PhantomMemorySystem = Depends(get_system),
):
    if entity_id:
        episodes = system.episode_store.find_by_entity(entity_id)
    elif start_time and end_time:
        episodes = system.episode_store.find_in_range(start_time, end_time)
    else:
        episodes = system.episode_store.all()
    return {"count": len(episodes), "episodes": [e.model_dump(mode="json") for e in episodes]}


@router.get("/{episode_id}")
def get_episode(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    ep = system.episode_store.get(episode_id)
    if ep is None:
        raise HTTPException(404, f"episode {episode_id} not found")
    return ep.model_dump(mode="json")


class TransitionRequest(BaseModel):
    note: str = ""


@router.post("/{episode_id}/validate")
def validate_episode(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    return system.episode_lifecycle.validate(episode_id).model_dump(mode="json")


@router.post("/{episode_id}/reject")
def reject_episode(episode_id: str, req: TransitionRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.episode_lifecycle.reject(episode_id, req.note).model_dump(mode="json")


@router.post("/{episode_id}/close")
def close_episode(episode_id: str, req: TransitionRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.episode_lifecycle.close(episode_id, req.note).model_dump(mode="json")


@router.post("/{episode_id}/archive")
def archive_episode(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    return system.episode_lifecycle.archive(episode_id).model_dump(mode="json")


class MergeRequest(BaseModel):
    episode_ids: list[str]
    title: Optional[str] = None


@router.post("/merge")
def merge_episodes(req: MergeRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.episode_lifecycle.merge(req.episode_ids, req.title).model_dump(mode="json")


class SplitRequest(BaseModel):
    episode_id: str
    event_id_groups: list[list[str]]
    titles: Optional[list[str]] = None


@router.post("/split")
def split_episode(req: SplitRequest, system: PhantomMemorySystem = Depends(get_system)):
    children = system.episode_lifecycle.split(req.episode_id, req.event_id_groups, req.titles)
    return {"children": [c.model_dump(mode="json") for c in children]}


@router.get("/{episode_id}/causal-hypotheses")
def causal_hypotheses(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    ep = system.episode_store.get(episode_id)
    if ep is None:
        raise HTTPException(404, f"episode {episode_id} not found")
    events = [system.store.get(eid) for eid in ep.event_ids]
    events = [e for e in events if e is not None]
    events.sort(key=lambda e: e.timestamps.event_time)
    hypotheses = []
    for i in range(len(events) - 1):
        h = system.causal.evaluate(events[i], events[i + 1])
        hypotheses.append(h.model_dump(mode="json"))
    return {"episode_id": episode_id, "hypotheses": hypotheses}


@router.get("/{episode_id}/divergence")
def first_divergence(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    from phantom_memory.analysis.divergence import BehavioralBaseline

    ep = system.episode_store.get(episode_id)
    if ep is None:
        raise HTTPException(404, f"episode {episode_id} not found")
    events = [system.store.get(eid) for eid in ep.event_ids]
    events = [e for e in events if e is not None]

    baseline_events = system.store.query(
        end_time=events[0].timestamps.event_time if events else None, limit=5000
    )
    baseline = BehavioralBaseline.from_events(baseline_events)
    findings = system.divergence.find(events, baseline)
    overall = system.divergence.overall_first_divergence(findings)
    return {
        "episode_id": episode_id,
        "findings": {k: (v.__dict__ if v else None) for k, v in findings.items()},
        "overall_first_divergence": overall.__dict__ if overall else None,
    }


@router.get("/{episode_id}/confidence")
def episode_confidence(episode_id: str, system: PhantomMemorySystem = Depends(get_system)):
    ep = system.episode_store.get(episode_id)
    if ep is None:
        raise HTTPException(404, f"episode {episode_id} not found")
    events = [system.store.get(eid) for eid in ep.event_ids]
    events = [e for e in events if e is not None]
    breakdown = system.confidence.score_episode(ep, events)
    return breakdown.as_dict()
