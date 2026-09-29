"""
Security Episode Engine / Episode Reconstruction Engine.

Turns a set of individually-unremarkable events into meaningful Episodes:
Authentication Episode, Process Execution Episode, Network Communication
Episode, Configuration Change Episode, Service Restart Episode, Privilege
Change Episode, File Access Episode, Incident Episode.

Linkage uses temporal proximity + shared entities + graph connectivity —
never bare co-occurrence alone. Every episode records which evidence
(event IDs, graph edges) supports it and a confidence in [0, 1]; nothing
here claims definite causality (see `analysis.causal` for that distinction).
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.core.models import CanonicalSecurityEvent, EventCategory, Episode
from phantom_memory.graph.memory_graph import SecurityMemoryGraph
from phantom_memory.graph.search import GraphQueryOptions, GraphSearchEngine
from phantom_memory.utils.ids import new_episode_id

ALGO_VERSION = "episode-engine-1.0.0"

_CATEGORY_TO_EPISODE_TYPE = {
    EventCategory.AUTHENTICATION: "authentication_episode",
    EventCategory.AUTHORIZATION: "privilege_change_episode",
    EventCategory.PROCESS: "process_execution_episode",
    EventCategory.PROCESS_TREE: "process_execution_episode",
    EventCategory.NETWORK_CONNECTION: "network_communication_episode",
    EventCategory.CONFIGURATION_CHANGE: "configuration_change_episode",
    EventCategory.SERVICE_LIFECYCLE: "service_restart_episode",
    EventCategory.FILE_ACTIVITY: "file_access_episode",
}


class _UnionFind:
    def __init__(self, items: list[str]):
        self.parent = {i: i for i in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


class EpisodeReconstructionEngine:
    def __init__(self, store: EventStore, memory_graph: SecurityMemoryGraph):
        self.store = store
        self.mg = memory_graph
        self.search = GraphSearchEngine(memory_graph)

    def reconstruct(
        self,
        events: list[CanonicalSecurityEvent],
        *,
        time_window: timedelta = timedelta(minutes=15),
        graph_hop_limit: int = 2,
    ) -> list[Episode]:
        if not events:
            return []
        events = sorted(events, key=lambda e: e.timestamps.event_time)
        uf = _UnionFind([e.event_id for e in events])

        # Pass 1: link events that share an entity and fall within the time window.
        by_entity: dict[str, list[CanonicalSecurityEvent]] = defaultdict(list)
        for e in events:
            for ent in e.entity_ids:
                by_entity[ent].append(e)

        for ent, ev_list in by_entity.items():
            ev_list.sort(key=lambda e: e.timestamps.event_time)
            for i in range(len(ev_list) - 1):
                a, b = ev_list[i], ev_list[i + 1]
                if (b.timestamps.event_time - a.timestamps.event_time) <= time_window:
                    uf.union(a.event_id, b.event_id)

        # Pass 2: link events whose entities are graph-connected within a small
        # hop limit (e.g. a process that spawned a child which then opened a
        # connection) even if the events don't literally share an entity ID.
        event_by_id = {e.event_id: e for e in events}
        entity_owner: dict[str, list[str]] = defaultdict(list)  # entity_id -> event_ids
        for e in events:
            for ent in e.entity_ids:
                entity_owner[ent].append(e.event_id)

        entities = list(entity_owner.keys())
        opts = GraphQueryOptions(depth_limit=graph_hop_limit, result_limit=50, timeout_seconds=3.0)
        for i, ent_a in enumerate(entities):
            neighborhood = self.search.multi_hop(ent_a, graph_hop_limit, opts)
            reachable = {n for layer in neighborhood.values() for n in layer}
            for ent_b in reachable:
                if ent_b in entity_owner:
                    for eid_a in entity_owner[ent_a]:
                        for eid_b in entity_owner[ent_b]:
                            ea, eb = event_by_id[eid_a], event_by_id[eid_b]
                            if abs((ea.timestamps.event_time - eb.timestamps.event_time)) <= time_window * 2:
                                uf.union(eid_a, eid_b)

        # Group events by connected component.
        groups: dict[str, list[CanonicalSecurityEvent]] = defaultdict(list)
        for e in events:
            groups[uf.find(e.event_id)].append(e)

        episodes: list[Episode] = []
        for group_events in groups.values():
            group_events.sort(key=lambda e: e.timestamps.event_time)
            episodes.append(self._build_episode(group_events))
        return episodes

    def _build_episode(self, group_events: list[CanonicalSecurityEvent]) -> Episode:
        category_counts: dict[EventCategory, int] = defaultdict(int)
        entity_ids: set[str] = set()
        for e in group_events:
            category_counts[e.event_category] += 1
            entity_ids.update(e.entity_ids)

        dominant_category = max(category_counts, key=category_counts.get)
        episode_type = _CATEGORY_TO_EPISODE_TYPE.get(dominant_category, "generic_episode")

        confidence = self._confidence(group_events, entity_ids)

        first, last = group_events[0], group_events[-1]
        episode = Episode(
            episode_id=new_episode_id(),
            episode_type=episode_type,
            title=self._title_for(episode_type, group_events),
            start_time=first.timestamps.event_time,
            end_time=last.timestamps.event_time,
            entity_ids=sorted(entity_ids),
            event_ids=[e.event_id for e in group_events],
            confidence=confidence,
            context={
                "event_count": len(group_events),
                "category_breakdown": {k.value: v for k, v in category_counts.items()},
                "algorithm_version": ALGO_VERSION,
            },
            trigger_event_id=first.event_id,
            status="candidate",
        )
        self.store.write_derived(
            artifact_id=episode.episode_id,
            artifact_type="episode",
            event_ids=episode.event_ids,
            payload=episode.model_dump(mode="json"),
            algorithm_version=ALGO_VERSION,
        )
        return episode

    @staticmethod
    def _confidence(events: list[CanonicalSecurityEvent], entity_ids: set[str]) -> float:
        if len(events) <= 1:
            return 0.3
        avg_event_confidence = sum(e.confidence for e in events) / len(events)
        density = min(1.0, len(events) / max(1, len(entity_ids)) / 3.0)
        span = (events[-1].timestamps.event_time - events[0].timestamps.event_time).total_seconds()
        tightness = 1.0 if span <= 60 else max(0.2, 1.0 - (span / 3600.0))
        return round(min(1.0, 0.4 * avg_event_confidence + 0.3 * density + 0.3 * tightness), 4)

    @staticmethod
    def _title_for(episode_type: str, events: list[CanonicalSecurityEvent]) -> str:
        readable = episode_type.replace("_", " ").title()
        span_start = events[0].timestamps.event_time.strftime("%Y-%m-%d %H:%M:%S")
        return f"{readable} ({len(events)} events, starting {span_start} UTC)"


class EpisodeStore:
    """Thin query layer over episodes persisted as derived artifacts."""

    def __init__(self, store: EventStore):
        self.store = store

    def all(self) -> list[Episode]:
        return [Episode.model_validate(a["payload"]) for a in self.store.get_derived("episode")]

    def get(self, episode_id: str) -> Optional[Episode]:
        for a in self.store.get_derived("episode"):
            if a["artifact_id"] == episode_id:
                return Episode.model_validate(a["payload"])
        return None

    def find_by_entity(self, entity_id: str) -> list[Episode]:
        return [ep for ep in self.all() if entity_id in ep.entity_ids]

    def find_in_range(self, start: datetime, end: datetime) -> list[Episode]:
        return [
            ep for ep in self.all()
            if ep.start_time <= end and (ep.end_time or ep.start_time) >= start
        ]
