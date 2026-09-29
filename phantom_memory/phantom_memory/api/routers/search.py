"""
/api/v1/search — hybrid retrieval and historical similarity.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from phantom_memory.api.deps import get_system
from phantom_memory.retrieval.similarity import IncidentFingerprint
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/search", tags=["search"])


class HybridSearchRequest(BaseModel):
    query: str
    anchor_entity_id: Optional[str] = None
    top_k: int = 20


@router.post("/hybrid")
def hybrid_search(req: HybridSearchRequest, system: PhantomMemorySystem = Depends(get_system)):
    episodes = system.episode_store.all()
    corpus = {ep.episode_id: f"{ep.title} {ep.episode_type} {' '.join(ep.entity_ids)}" for ep in episodes}
    hits = system.hybrid_retrieval.search(
        req.query, corpus=corpus, anchor_entity_id=req.anchor_entity_id, top_k=req.top_k
    )
    return {"count": len(hits), "hits": [h.__dict__ for h in hits]}


@router.get("/similar-episodes/{episode_id}")
def similar_episodes(episode_id: str, top_k: int = 5, system: PhantomMemorySystem = Depends(get_system)):
    subject_ep = system.episode_store.get(episode_id)
    if subject_ep is None:
        raise HTTPException(404, f"episode {episode_id} not found")
    all_eps = system.episode_store.all()

    def fingerprint_for(ep):
        events = [system.store.get(eid) for eid in ep.event_ids]
        events = [e for e in events if e is not None]
        return IncidentFingerprint.from_events(ep.episode_id, events)

    subject_fp = fingerprint_for(subject_ep)
    candidate_fps = [fingerprint_for(ep) for ep in all_eps if ep.episode_id != episode_id]
    results = system.similarity.rank(subject_fp, candidate_fps, top_k=top_k)
    return {"episode_id": episode_id, "similar": [r.as_dict() for r in results]}
