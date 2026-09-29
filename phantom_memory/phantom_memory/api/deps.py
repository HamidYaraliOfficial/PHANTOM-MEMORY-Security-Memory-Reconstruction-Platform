"""Shared FastAPI dependencies."""
from __future__ import annotations

from fastapi import Request

from phantom_memory.system import PhantomMemorySystem


def get_system(request: Request) -> PhantomMemorySystem:
    return request.app.state.system
