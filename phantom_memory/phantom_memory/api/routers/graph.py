"""
/api/v1/graph — entities, edges, traversal, and point-in-time state.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from phantom_memory.api.deps import get_system
from phantom_memory.graph.search import GraphQueryOptions
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/graph", tags=["graph"])


@router.get("/entities/{entity_id}")
def get_entity(entity_id: str, system: PhantomMemorySystem = Depends(get_system)):
    entity = system.graph.get_entity(entity_id)
    if entity is None:
        raise HTTPException(404, f"entity {entity_id} not found")
    return entity.model_dump(mode="json")


@router.get("/entities/{entity_id}/neighbors")
def neighbors(
    entity_id: str,
    depth_limit: int = 2,
    result_limit: int = 100,
    min_confidence: float = 0.0,
    system: PhantomMemorySystem = Depends(get_system),
):
    opts = GraphQueryOptions(depth_limit=depth_limit, result_limit=result_limit, min_confidence=min_confidence)
    return {"entity_id": entity_id, "neighbors": system.graph_search.neighbors(entity_id, opts)}


@router.get("/entities/{entity_id}/timeline")
def entity_timeline(entity_id: str, system: PhantomMemorySystem = Depends(get_system)):
    return {"entity_id": entity_id, "timeline": system.temporal_memory.entity_timeline(entity_id)}


@router.get("/paths")
def shortest_paths(
    source: str, target: str, k: int = 3, depth_limit: int = 6,
    system: PhantomMemorySystem = Depends(get_system),
):
    opts = GraphQueryOptions(depth_limit=depth_limit)
    results = system.graph_search.shortest_paths(source, target, opts, k=k)
    return {"paths": [{"path": r.path, "confidence": r.total_confidence} for r in results]}


@router.get("/state-at")
def state_at(at_time: datetime, system: PhantomMemorySystem = Depends(get_system)):
    from dataclasses import asdict as _asdict
    return _asdict(system.temporal_memory.state_at(at_time))


@router.get("/summary")
def graph_summary(system: PhantomMemorySystem = Depends(get_system)):
    return {"node_count": system.graph.node_count(), "edge_count": system.graph.edge_count()}
