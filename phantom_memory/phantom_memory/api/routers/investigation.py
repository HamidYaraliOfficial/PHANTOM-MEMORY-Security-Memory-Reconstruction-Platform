"""
/api/v1/investigation — notebooks and evidence bookmarks.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from phantom_memory.api.deps import get_system
from phantom_memory.system import PhantomMemorySystem

router = APIRouter(prefix="/api/v1/investigation", tags=["investigation"])


class CreateNotebookRequest(BaseModel):
    title: str
    case_id: Optional[str] = None


@router.post("/notebooks", status_code=201)
def create_notebook(req: CreateNotebookRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.notebooks.create(req.title, req.case_id).__dict__


@router.get("/notebooks/{notebook_id}")
def get_notebook(notebook_id: str, system: PhantomMemorySystem = Depends(get_system)):
    nb = system.notebooks.get(notebook_id)
    if nb is None:
        raise HTTPException(404, f"notebook {notebook_id} not found")
    return nb.__dict__


class AddEventsRequest(BaseModel):
    event_ids: list[str]


@router.post("/notebooks/{notebook_id}/events")
def add_events(notebook_id: str, req: AddEventsRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.notebooks.add_events(notebook_id, req.event_ids).__dict__


class AddEntryRequest(BaseModel):
    kind: str
    content: str


@router.post("/notebooks/{notebook_id}/entries")
def add_entry(notebook_id: str, req: AddEntryRequest, system: PhantomMemorySystem = Depends(get_system)):
    return system.notebooks.add_entry(notebook_id, req.kind, req.content).__dict__


class BookmarkRequest(BaseModel):
    subject_type: str
    subject_ref: str
    annotation: str
    analyst: str
    case_id: Optional[str] = None


@router.post("/bookmarks", status_code=201)
def create_bookmark(req: BookmarkRequest, system: PhantomMemorySystem = Depends(get_system)):
    try:
        return system.bookmarks.create(
            req.subject_type, req.subject_ref, req.annotation, req.analyst, req.case_id
        ).__dict__
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/bookmarks")
def list_bookmarks(case_id: Optional[str] = None, system: PhantomMemorySystem = Depends(get_system)):
    if case_id:
        return {"bookmarks": [b.__dict__ for b in system.bookmarks.list_for_case(case_id)]}
    return {"bookmarks": [b.__dict__ for b in system.bookmarks.list_all()]}
