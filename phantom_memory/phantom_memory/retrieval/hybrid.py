"""
Hybrid Security Memory Retrieval Engine.

For a question or incident, combines Keyword Search + Vector Search + Graph
Traversal + Temporal Filtering + Entity Resolution + Provenance Filtering,
then produces a ranked, explainable result: every hit carries the list of
retrieval channels that surfaced it and why.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.graph.search import GraphQueryOptions, GraphSearchEngine
from phantom_memory.retrieval.vector_index import VectorMemoryIndex


@dataclass
class RetrievalHit:
    doc_id: str
    combined_score: float
    channels: list[str] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class HybridRetrievalEngine:
    def __init__(self, store: EventStore, graph_search: GraphSearchEngine, vector_index: VectorMemoryIndex):
        self.store = store
        self.graph_search = graph_search
        self.vector_index = vector_index

    def _keyword_hits(self, query: str, corpus: dict[str, str]) -> dict[str, float]:
        terms = [t.lower() for t in query.split() if t.strip()]
        scores: dict[str, float] = {}
        for doc_id, text in corpus.items():
            text_lower = text.lower()
            matches = sum(text_lower.count(t) for t in terms)
            if matches:
                scores[doc_id] = min(1.0, matches / max(1, len(terms)) / 3.0)
        return scores

    def search(
        self,
        query: str,
        *,
        corpus: dict[str, str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        anchor_entity_id: Optional[str] = None,
        provenance_sources: Optional[list[str]] = None,
        top_k: int = 20,
    ) -> list[RetrievalHit]:
        combined: dict[str, RetrievalHit] = {}

        keyword_scores = self._keyword_hits(query, corpus)
        for doc_id, score in keyword_scores.items():
            hit = combined.setdefault(doc_id, RetrievalHit(doc_id=doc_id, combined_score=0.0))
            hit.combined_score += 0.35 * score
            hit.channels.append("keyword")
            hit.explanation.append(f"keyword overlap score={score:.2f}")

        for vhit in self.vector_index.search(query, top_k=top_k * 2):
            hit = combined.setdefault(vhit.doc_id, RetrievalHit(doc_id=vhit.doc_id, combined_score=0.0))
            hit.combined_score += 0.45 * vhit.score
            hit.channels.append("vector")
            hit.metadata.update(vhit.metadata)
            hit.explanation.append(f"semantic similarity={vhit.score:.2f}")

        if anchor_entity_id:
            opts = GraphQueryOptions(start_time=start_time, end_time=end_time, depth_limit=2, result_limit=100)
            for neighbor in self.graph_search.neighbors(anchor_entity_id, opts):
                doc_id = neighbor.get("neighbor")
                if doc_id in combined:
                    combined[doc_id].combined_score += 0.2
                    combined[doc_id].channels.append("graph")
                    combined[doc_id].explanation.append(
                        f"graph-connected to {anchor_entity_id} via {neighbor.get('edge_type')}"
                    )

        if provenance_sources:
            for doc_id, hit in list(combined.items()):
                src = hit.metadata.get("source")
                if src and src not in provenance_sources:
                    del combined[doc_id]

        ranked = sorted(combined.values(), key=lambda h: h.combined_score, reverse=True)
        return ranked[:top_k]
