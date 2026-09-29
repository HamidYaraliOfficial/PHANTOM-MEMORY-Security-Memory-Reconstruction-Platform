"""
/api/v1/replay — snapshots, temporal diff, and event replay control.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from phantom_memory.api.deps import get_system
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/replay", tags=["replay"])


class SnapshotRequest(BaseModel):
    at_time: datetime
    label: Optional[str] = None


@router.post("/snapshots")
def create_snapshot(req: SnapshotRequest, system: PhantomMemorySystem = Depends(get_system)):
    snap = system.snapshots.create_snapshot(req.at_time, req.label)
    return snap.__dict__


@router.get("/snapshots")
def list_snapshots(system: PhantomMemorySystem = Depends(get_system)):
    return {"snapshots": system.snapshots.list_snapshots()}


@router.get("/diff")
def temporal_diff(from_time: datetime, to_time: datetime, system: PhantomMemorySystem = Depends(get_system)):
    from dataclasses import asdict
    return asdict(system.temporal_diff.diff(from_time, to_time))


class ReplayLoadRequest(BaseModel):
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    host_id: Optional[str] = None


@router.post("/load")
def replay_load(req: ReplayLoadRequest, system: PhantomMemorySystem = Depends(get_system)):
    progress = system.replay.load(start_time=req.start_time, end_time=req.end_time, host_id=req.host_id)
    return progress.__dict__


@router.post("/step")
def replay_step(system: PhantomMemorySystem = Depends(get_system)):
    event = system.replay.step(lambda e: system._project_to_graph(e))
    return {"event": event.model_dump(mode="json") if event else None, "progress": system.replay.progress.__dict__}


@router.post("/play")
def replay_play(max_events: Optional[int] = None, system: PhantomMemorySystem = Depends(get_system)):
    progress = system.replay.play(lambda e: system._project_to_graph(e), max_events=max_events)
    return progress.__dict__


@router.post("/pause")
def replay_pause(system: PhantomMemorySystem = Depends(get_system)):
    system.replay.pause()
    return system.replay.progress.__dict__


@router.post("/resume")
def replay_resume(system: PhantomMemorySystem = Depends(get_system)):
    system.replay.resume()
    return system.replay.progress.__dict__


@router.post("/cancel")
def replay_cancel(system: PhantomMemorySystem = Depends(get_system)):
    system.replay.cancel()
    return system.replay.progress.__dict__


@router.get("/progress")
def replay_progress(system: PhantomMemorySystem = Depends(get_system)):
    return system.replay.progress.__dict__
