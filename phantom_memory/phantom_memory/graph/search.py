"""
Memory Graph Search Engine.

Provides traversal, path search, temporal queries, neighbor search, subgraph
search, relationship filtering and multi-hop analysis over the Security
Memory Graph. Every query accepts a time range, result limit, depth limit,
and timeout, and supports cooperative cancellation via a `threading.Event`
so a long-running exploratory query from the UI/API can be aborted cleanly.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import networkx as nx

from phantom_memory.graph.memory_graph import SecurityMemoryGraph


class QueryTimeoutError(Exception):
    pass


class QueryCancelledError(Exception):
    pass


@dataclass
class GraphQueryOptions:
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    edge_types: Optional[list[str]] = None
    min_confidence: float = 0.0
    depth_limit: int = 4
    result_limit: int = 200
    timeout_seconds: float = 10.0
    cancel_event: Optional[threading.Event] = None


@dataclass
class PathResult:
    path: list[str]
    edge_ids: list[str]
    total_confidence: float


class GraphSearchEngine:
    def __init__(self, memory_graph: SecurityMemoryGraph):
        self.mg = memory_graph

    def _deadline_guard(self, start_ts: float, opts: GraphQueryOptions) -> None:
        if opts.cancel_event is not None and opts.cancel_event.is_set():
            raise QueryCancelledError("query cancelled")
        if time.monotonic() - start_ts > opts.timeout_seconds:
            raise QueryTimeoutError(f"graph query exceeded {opts.timeout_seconds}s")

    def _filtered_view(self, opts: GraphQueryOptions) -> nx.MultiDiGraph:
        g = self.mg.graph
        if not opts.edge_types and opts.min_confidence <= 0.0 and not opts.start_time and not opts.end_time:
            return g
        view = nx.MultiDiGraph()
        view.add_nodes_from(g.nodes(data=True))
        for u, v, k, data in g.edges(keys=True, data=True):
            if opts.edge_types and data.get("edge_type") not in opts.edge_types:
                continue
            if data.get("confidence", 0.0) < opts.min_confidence:
                continue
            vf = data.get("valid_from")
            if vf and opts.start_time and vf < opts.start_time.isoformat():
                continue
            if vf and opts.end_time and vf > opts.end_time.isoformat():
                continue
            view.add_edge(u, v, key=k, **data)
        return view

    # ---- neighbor / subgraph search -------------------------------------- #
    def neighbors(self, entity_id: str, opts: Optional[GraphQueryOptions] = None) -> list[dict]:
        opts = opts or GraphQueryOptions()
        start_ts = time.monotonic()
        g = self._filtered_view(opts)
        results = []
        if entity_id not in g:
            return results
        for _, v, data in g.out_edges(entity_id, data=True):
            self._deadline_guard(start_ts, opts)
            results.append({"neighbor": v, "direction": "out", **data})
        for u, _, data in g.in_edges(entity_id, data=True):
            self._deadline_guard(start_ts, opts)
            results.append({"neighbor": u, "direction": "in", **data})
        return results[: opts.result_limit]

    def subgraph(self, entity_ids: list[str], opts: Optional[GraphQueryOptions] = None) -> nx.MultiDiGraph:
        opts = opts or GraphQueryOptions()
        g = self._filtered_view(opts)
        nodes = set(entity_ids)
        start_ts = time.monotonic()
        for eid in entity_ids:
            self._deadline_guard(start_ts, opts)
            if eid not in g:
                continue
            nodes |= self._bounded_bfs(g, eid, opts, start_ts)
        return g.subgraph(nodes).copy()

    def _bounded_bfs(self, g: nx.MultiDiGraph, source: str, opts: GraphQueryOptions, start_ts: float) -> set:
        visited = {source}
        frontier = [source]
        depth = 0
        while frontier and depth < opts.depth_limit and len(visited) < opts.result_limit:
            self._deadline_guard(start_ts, opts)
            next_frontier = []
            for node in frontier:
                for _, v in g.out_edges(node):
                    if v not in visited:
                        visited.add(v)
                        next_frontier.append(v)
                for u, _ in g.in_edges(node):
                    if u not in visited:
                        visited.add(u)
                        next_frontier.append(u)
                if len(visited) >= opts.result_limit:
                    break
            frontier = next_frontier
            depth += 1
        return visited

    # ---- multi-hop traversal ------------------------------------------------ #
    def multi_hop(self, entity_id: str, hops: int, opts: Optional[GraphQueryOptions] = None) -> dict[int, list[str]]:
        opts = opts or GraphQueryOptions(depth_limit=hops)
        opts.depth_limit = min(opts.depth_limit, hops)
        g = self._filtered_view(opts)
        start_ts = time.monotonic()
        layers: dict[int, list[str]] = {0: [entity_id]}
        visited = {entity_id}
        frontier = [entity_id]
        for depth in range(1, hops + 1):
            self._deadline_guard(start_ts, opts)
            next_frontier = []
            for node in frontier:
                if node not in g:
                    continue
                for _, v in g.out_edges(node):
                    if v not in visited:
                        visited.add(v)
                        next_frontier.append(v)
            layers[depth] = next_frontier
            frontier = next_frontier
            if len(visited) >= opts.result_limit:
                break
        return layers

    # ---- path search ---------------------------------------------------------- #
    def shortest_paths(
        self, source: str, target: str, opts: Optional[GraphQueryOptions] = None, k: int = 3
    ) -> list[PathResult]:
        opts = opts or GraphQueryOptions()
        g = self._filtered_view(opts)
        if source not in g or target not in g:
            return []
        start_ts = time.monotonic()
        # shortest_simple_paths does not support MultiGraph, so collapse to a
        # simple undirected graph for path-finding purposes; edge metadata is
        # looked back up from the original multigraph below.
        simple_undirected = nx.Graph(g)
        try:
            gen = nx.shortest_simple_paths(simple_undirected, source, target)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []
        results: list[PathResult] = []
        for i, path in enumerate(gen):
            self._deadline_guard(start_ts, opts)
            if i >= k or len(path) - 1 > opts.depth_limit:
                break
            edge_ids, confidences = [], []
            for a, b in zip(path[:-1], path[1:]):
                edge_data = None
                if g.has_edge(a, b):
                    edge_data = list(g.get_edge_data(a, b).values())[0]
                elif g.has_edge(b, a):
                    edge_data = list(g.get_edge_data(b, a).values())[0]
                if edge_data:
                    confidences.append(edge_data.get("confidence", 0.5))
            results.append(
                PathResult(
                    path=path,
                    edge_ids=edge_ids,
                    total_confidence=sum(confidences) / len(confidences) if confidences else 0.0,
                )
            )
        return results

    def relationship_filter(self, edge_types: list[str], opts: Optional[GraphQueryOptions] = None) -> list[dict]:
        opts = opts or GraphQueryOptions()
        opts.edge_types = edge_types
        g = self._filtered_view(opts)
        start_ts = time.monotonic()
        out = []
        for u, v, data in g.edges(data=True):
            self._deadline_guard(start_ts, opts)
            out.append({"source": u, "target": v, **data})
            if len(out) >= opts.result_limit:
                break
        return out
