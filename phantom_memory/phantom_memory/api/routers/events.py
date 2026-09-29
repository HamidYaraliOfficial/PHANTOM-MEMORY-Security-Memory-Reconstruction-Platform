"""
/api/v1/events — ingest and query canonical security events.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from phantom_memory.api.deps import get_system
from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.post("", status_code=201)
def ingest_event(event: CanonicalSecurityEvent, system: PhantomMemorySystem = Depends(get_system)):
    result = system.ingest(event)
    if not result.accepted:
        return {
            "accepted": False,
            "reason": result.reason,
            "was_duplicate": result.was_duplicate,
            "clock_notes": result.clock_notes,
        }
    return {
        "accepted": True,
        "event_id": result.event.event_id,
        "importance_score": result.event.importance_score,
        "importance_tier": result.event.importance_tier.value,
        "clock_notes": result.clock_notes,
    }


@router.get("/{event_id}")
def get_event(event_id: str, system: PhantomMemorySystem = Depends(get_system)):
    event = system.store.get(event_id)
    if event is None:
        raise HTTPException(404, f"event {event_id} not found")
    enrichments = system.store.get_enrichments(event_id)
    return {"event": event.model_dump(mode="json"), "enrichments": enrichments}


@router.get("")
def query_events(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_category: Optional[str] = None,
    host_id: Optional[str] = None,
    entity_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    min_importance: Optional[float] = None,
    limit: int = 200,
    system: PhantomMemorySystem = Depends(get_system),
):
    events = system.store.query(
        start_time=start_time, end_time=end_time, event_category=event_category,
        host_id=host_id, entity_id=entity_id, correlation_id=correlation_id,
        min_importance=min_importance, limit=limit,
    )
    return {"count": len(events), "events": [e.model_dump(mode="json") for e in events]}


@router.get("/stats/summary")
def store_summary(system: PhantomMemorySystem = Depends(get_system)):
    return {"total_events": system.store.count()}
