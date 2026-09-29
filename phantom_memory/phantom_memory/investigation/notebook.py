"""
Investigation Notebook & Investigation Query Recorder.

A Notebook holds everything an analyst assembled while investigating:
timeline references, a graph subset, an event set, recorded queries, notes,
hypotheses, evidence references and conclusions — versioned, and replayable
because every recorded query can be re-run against a snapshot or a fresh
dataset.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.utils.ids import new_note_id, new_query_id

ALGO_VERSION = "investigation-notebook-1.0.0"


@dataclass
class RecordedQuery:
    query_id: str
    tool: str
    parameters: dict
    result_summary: str
    recorded_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class NotebookEntry:
    entry_id: str
    kind: str  # 'note' | 'hypothesis' | 'conclusion' | 'evidence_ref'
    content: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class Notebook:
    notebook_id: str
    case_id: Optional[str]
    title: str
    event_set: list[str] = field(default_factory=list)
    graph_subset_entity_ids: list[str] = field(default_factory=list)
    recorded_queries: list[dict] = field(default_factory=list)
    entries: list[dict] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    version: int = 1


class InvestigationNotebook:
    def __init__(self, store: EventStore):
        self.store = store

    def _persist(self, nb: Notebook) -> None:
        self.store.write_derived(
            artifact_id=nb.notebook_id,
            artifact_type="notebook",
            event_ids=nb.event_set,
            payload=nb.__dict__,
            algorithm_version=ALGO_VERSION,
        )

    def create(self, title: str, case_id: Optional[str] = None) -> Notebook:
        nb = Notebook(notebook_id=f"nbk_{new_note_id()}", case_id=case_id, title=title)
        self._persist(nb)
        return nb

    def get(self, notebook_id: str) -> Optional[Notebook]:
        for a in self.store.get_derived("notebook"):
            if a["artifact_id"] == notebook_id:
                return Notebook(**a["payload"])
        return None

    def add_events(self, notebook_id: str, event_ids: list[str]) -> Notebook:
        nb = self._require(notebook_id)
        for eid in event_ids:
            if eid not in nb.event_set:
                nb.event_set.append(eid)
        return self._touch(nb)

    def add_graph_subset(self, notebook_id: str, entity_ids: list[str]) -> Notebook:
        nb = self._require(notebook_id)
        for eid in entity_ids:
            if eid not in nb.graph_subset_entity_ids:
                nb.graph_subset_entity_ids.append(eid)
        return self._touch(nb)

    def record_query(self, notebook_id: str, tool: str, parameters: dict, result_summary: str) -> RecordedQuery:
        nb = self._require(notebook_id)
        rq = RecordedQuery(query_id=new_query_id(), tool=tool, parameters=parameters, result_summary=result_summary)
        nb.recorded_queries.append(rq.__dict__)
        self._touch(nb)
        return rq

    def add_entry(self, notebook_id: str, kind: str, content: str) -> NotebookEntry:
        nb = self._require(notebook_id)
        entry = NotebookEntry(entry_id=new_note_id(), kind=kind, content=content)
        nb.entries.append(entry.__dict__)
        self._touch(nb)
        return entry

    def replay_query(self, notebook_id: str, query_id: str, tool_registry: dict[str, Callable[..., Any]]) -> Any:
        """Re-execute a previously recorded query by looking its tool up in a
        registry the caller supplies (e.g. {'search_events': store.query,
        'graph_neighbors': graph_search.neighbors, ...})."""
        nb = self._require(notebook_id)
        record = next((q for q in nb.recorded_queries if q["query_id"] == query_id), None)
        if record is None:
            raise KeyError(f"query {query_id} not found in notebook {notebook_id}")
        fn = tool_registry.get(record["tool"])
        if fn is None:
            raise KeyError(f"tool '{record['tool']}' not found in registry")
        return fn(**record["parameters"])

    def _touch(self, nb: Notebook) -> Notebook:
        nb.updated_at = datetime.now(timezone.utc).isoformat()
        nb.version += 1
        self._persist(nb)
        return nb

    def _require(self, notebook_id: str) -> Notebook:
        nb = self.get(notebook_id)
        if nb is None:
            raise KeyError(f"notebook {notebook_id} not found")
        return nb
