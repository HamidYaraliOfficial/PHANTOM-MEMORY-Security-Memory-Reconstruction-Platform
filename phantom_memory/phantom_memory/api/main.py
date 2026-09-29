"""
PHANTOM MEMORY API Platform.

Versioned REST API (FastAPI) plus a WebSocket channel for live event
ingestion / episode / replay progress updates. Includes a Self-Memory
Health Layer so the platform's own subsystems (event ingestion, graph
storage, vector index, replay engine) are observable — the point being
that PHANTOM MEMORY should never mistake its own outage for a security
incident.
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from phantom_memory.api.routers import cases, episodes, events, graph, investigation, replay, search
from phantom_memory.system import PhantomMemorySystem

_START_TIME = time.time()


class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, message: dict):
        stale = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.system = PhantomMemorySystem(data_dir="data")
    app.state.ws_manager = ConnectionManager()
    yield


def create_app(data_dir: str = "data") -> FastAPI:
    app = FastAPI(
        title="PHANTOM MEMORY API",
        description="Security Memory Reconstruction Platform — core backend API.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    )

    app.include_router(events.router)
    app.include_router(graph.router)
    app.include_router(episodes.router)
    app.include_router(search.router)
    app.include_router(replay.router)
    app.include_router(cases.router)
    app.include_router(investigation.router)

    @app.get("/api/v1/health/live", tags=["health"])
    def liveness():
        return {"status": "alive", "uptime_seconds": round(time.time() - _START_TIME, 2)}

    @app.get("/api/v1/health/ready", tags=["health"])
    def readiness():
        system: PhantomMemorySystem = app.state.system
        checks = {
            "event_store": _safe_check(lambda: system.store.count() >= 0),
            "graph_storage": _safe_check(lambda: system.graph.node_count() >= 0),
            "vector_index": _safe_check(lambda: system.vector_index.size() >= 0),
            "replay_engine": _safe_check(lambda: system.replay.progress is not None),
        }
        healthy = all(checks.values())
        return {"status": "ready" if healthy else "degraded", "checks": checks}

    @app.get("/api/v1/health/self", tags=["health"])
    def self_memory_health():
        """Self-Memory Health Layer: reports on PHANTOM MEMORY's own
        subsystems so a platform outage is never confused with a security
        incident by anything consuming this API."""
        system: PhantomMemorySystem = app.state.system
        return {
            "event_ingestion": {"total_events": system.store.count()},
            "graph_storage": {"nodes": system.graph.node_count(), "edges": system.graph.edge_count()},
            "vector_index": {"documents": system.vector_index.size()},
            "replay_engine": {"status": system.replay.progress.status.value},
            "uptime_seconds": round(time.time() - _START_TIME, 2),
        }

    @app.websocket("/ws/live")
    async def live_updates(websocket: WebSocket):
        manager: ConnectionManager = app.state.ws_manager
        await manager.connect(websocket)
        try:
            while True:
                # Clients may send control messages (e.g. subscribe filters);
                # this minimal loop just keeps the connection open and echoes
                # acknowledgements. Server-initiated broadcasts (new events,
                # episode updates, replay progress, case updates) are pushed
                # via manager.broadcast(...) from elsewhere in the app.
                data = await websocket.receive_json()
                await websocket.send_json({"ack": True, "received": data})
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    return app


def _safe_check(fn) -> bool:
    try:
        return bool(fn())
    except Exception:
        return False


app = create_app()
