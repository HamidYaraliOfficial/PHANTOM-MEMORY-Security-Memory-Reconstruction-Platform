"""
Temporal Memory Engine.

Answers "what was true about the system at timestamp T": which processes
were running, which network connections were open, which users were
authenticated, which configuration was active, and which services were
communicating with each other — reconstructed from temporal edges in the
Security Memory Graph rather than from any live agent state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from phantom_memory.core.models import EdgeType
from phantom_memory.graph.memory_graph import SecurityMemoryGraph


@dataclass
class SystemStateAtTime:
    at_time: datetime
    running_processes: list[dict] = field(default_factory=list)
    active_connections: list[dict] = field(default_factory=list)
    authenticated_users: list[dict] = field(default_factory=list)
    active_configuration: list[dict] = field(default_factory=list)
    service_communications: list[dict] = field(default_factory=list)
    evidence_event_count: int = 0
    confidence: float = 0.0


class TemporalMemoryEngine:
    def __init__(self, memory_graph: SecurityMemoryGraph):
        self.mg = memory_graph

    def state_at(self, at_time: datetime) -> SystemStateAtTime:
        state = SystemStateAtTime(at_time=at_time)

        executed = self.mg.edges_valid_at(at_time, EdgeType.EXECUTED)
        state.running_processes = [
            {"actor": e.source_entity_id, "process": e.target_entity_id,
             "since": e.valid_from.isoformat(), "confidence": e.confidence}
            for e in executed
        ]

        connected = self.mg.edges_valid_at(at_time, EdgeType.CONNECTED_TO)
        state.active_connections = [
            {"from": e.source_entity_id, "to": e.target_entity_id,
             "since": e.valid_from.isoformat(), "confidence": e.confidence}
            for e in connected
        ]

        authed = self.mg.edges_valid_at(at_time, EdgeType.AUTHENTICATED_TO)
        state.authenticated_users = [
            {"user": e.source_entity_id, "resource": e.target_entity_id,
             "since": e.valid_from.isoformat(), "confidence": e.confidence}
            for e in authed
        ]

        depends = self.mg.edges_valid_at(at_time, EdgeType.DEPENDS_ON)
        state.service_communications = [
            {"service": e.source_entity_id, "depends_on": e.target_entity_id,
             "confidence": e.confidence}
            for e in depends
        ]

        belongs = self.mg.edges_valid_at(at_time, EdgeType.BELONGS_TO)
        state.active_configuration = [
            {"entity": e.source_entity_id, "scope": e.target_entity_id, "confidence": e.confidence}
            for e in belongs
        ]

        all_edges = executed + connected + authed + depends + belongs
        state.evidence_event_count = sum(len(e.evidence_event_ids) for e in all_edges)
        state.confidence = (
            sum(e.confidence for e in all_edges) / len(all_edges) if all_edges else 0.0
        )
        return state

    def entity_timeline(self, entity_id: str) -> list[dict]:
        """All edges touching an entity, in chronological order — the basis
        for 'trace this entity through time' views."""
        edges = self.mg.edges_for_entity(entity_id)
        return [
            {
                "edge_id": e.edge_id,
                "edge_type": e.edge_type.value,
                "source": e.source_entity_id,
                "target": e.target_entity_id,
                "valid_from": e.valid_from.isoformat(),
                "valid_to": e.valid_to.isoformat() if e.valid_to else None,
                "confidence": e.confidence,
            }
            for e in sorted(edges, key=lambda x: x.valid_from)
        ]
