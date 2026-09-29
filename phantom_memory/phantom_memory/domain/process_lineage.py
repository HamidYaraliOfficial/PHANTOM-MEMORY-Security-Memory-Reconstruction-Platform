"""
Process Lineage Engine.

Maintains parent/child process history over time and connects process-tree
events to the network, file and user events those processes were
responsible for, so an analyst can answer "what did this process do, and
what did it spawn, across its entire life" from the graph alone.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from phantom_memory.core.models import EdgeType
from phantom_memory.graph.memory_graph import SecurityMemoryGraph


@dataclass
class ProcessLineageNode:
    process_entity_id: str
    children: list["ProcessLineageNode"] = field(default_factory=list)
    connections: list[str] = field(default_factory=list)
    files_touched: list[str] = field(default_factory=list)
    executed_by_user: str | None = None


class ProcessLineageEngine:
    def __init__(self, memory_graph: SecurityMemoryGraph):
        self.mg = memory_graph

    def build_tree(self, root_process_entity_id: str, max_depth: int = 8) -> ProcessLineageNode:
        return self._build(root_process_entity_id, max_depth)

    def _build(self, process_id: str, depth_remaining: int) -> ProcessLineageNode:
        node = ProcessLineageNode(process_entity_id=process_id)
        if depth_remaining <= 0:
            return node

        edges = self.mg.edges_for_entity(process_id, direction="out")
        for e in edges:
            if e.edge_type == EdgeType.SPAWNED:
                node.children.append(self._build(e.target_entity_id, depth_remaining - 1))
            elif e.edge_type == EdgeType.CONNECTED_TO:
                node.connections.append(e.target_entity_id)
            elif e.edge_type == EdgeType.MODIFIED or e.edge_type == EdgeType.ACCESSED:
                node.files_touched.append(e.target_entity_id)

        for e in self.mg.edges_for_entity(process_id, direction="in"):
            if e.edge_type == EdgeType.EXECUTED:
                node.executed_by_user = e.source_entity_id

        return node

    def ancestors(self, process_entity_id: str, max_depth: int = 16) -> list[str]:
        chain = []
        current = process_entity_id
        for _ in range(max_depth):
            parents = [
                e.source_entity_id
                for e in self.mg.edges_for_entity(current, direction="in")
                if e.edge_type == EdgeType.SPAWNED
            ]
            if not parents:
                break
            chain.append(parents[0])
            current = parents[0]
        return chain

    def flatten(self, node: ProcessLineageNode) -> list[str]:
        ids = [node.process_entity_id]
        for child in node.children:
            ids.extend(self.flatten(child))
        return ids
