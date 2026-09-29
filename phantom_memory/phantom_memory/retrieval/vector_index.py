"""
Vector Memory Index.

Converts Episode Summaries, Event Context, Incident Patterns, Behavior
Fingerprints and Security Narratives into vectors for semantic similarity
search. Implemented with a local TF-IDF + cosine-similarity model
(scikit-learn) so the platform's default configuration needs no external
model download or network access to embed security data — this matters for
a Privacy-Aware, Local-AI-first design. The `EmbeddingBackend` interface
below is intentionally small so a stronger embedding model (local
sentence-transformers, a self-hosted embedding server, etc.) can be swapped
in without touching callers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class EmbeddingBackend(ABC):
    @abstractmethod
    def fit(self, documents: list[str]) -> None: ...

    @abstractmethod
    def transform(self, documents: list[str]) -> np.ndarray: ...

    @property
    @abstractmethod
    def is_fitted(self) -> bool: ...


class TfidfEmbeddingBackend(EmbeddingBackend):
    def __init__(self, max_features: int = 20000):
        self._vectorizer = TfidfVectorizer(
            max_features=max_features, ngram_range=(1, 2), min_df=1, stop_words="english"
        )
        self._fitted = False

    def fit(self, documents: list[str]) -> None:
        if not documents:
            return
        self._vectorizer.fit(documents)
        self._fitted = True

    def transform(self, documents: list[str]) -> np.ndarray:
        if not self._fitted:
            return np.zeros((len(documents), 0))
        return self._vectorizer.transform(documents).toarray()

    @property
    def is_fitted(self) -> bool:
        return self._fitted


@dataclass
class VectorSearchHit:
    doc_id: str
    score: float
    metadata: dict


class VectorMemoryIndex:
    """
    A small, self-contained semantic index over arbitrary security-memory
    documents (episode summaries, event narratives, incident fingerprints).
    Re-fit is O(n) over stored documents — fine at investigative scale; a
    production deployment can swap in FAISS/pgvector behind this interface
    without changing calling code.
    """

    def __init__(self, backend: Optional[EmbeddingBackend] = None):
        self.backend = backend or TfidfEmbeddingBackend()
        self._doc_ids: list[str] = []
        self._documents: list[str] = []
        self._metadata: list[dict] = []
        self._matrix: Optional[np.ndarray] = None

    def upsert(self, doc_id: str, text: str, metadata: Optional[dict] = None) -> None:
        metadata = metadata or {}
        if doc_id in self._doc_ids:
            idx = self._doc_ids.index(doc_id)
            self._documents[idx] = text
            self._metadata[idx] = metadata
        else:
            self._doc_ids.append(doc_id)
            self._documents.append(text)
            self._metadata.append(metadata)
        self._rebuild()

    def upsert_many(self, items: list[tuple[str, str, dict]]) -> None:
        for doc_id, text, metadata in items:
            if doc_id in self._doc_ids:
                idx = self._doc_ids.index(doc_id)
                self._documents[idx] = text
                self._metadata[idx] = metadata
            else:
                self._doc_ids.append(doc_id)
                self._documents.append(text)
                self._metadata.append(metadata)
        self._rebuild()

    def _rebuild(self) -> None:
        if not self._documents:
            self._matrix = None
            return
        self.backend.fit(self._documents)
        self._matrix = self.backend.transform(self._documents)

    def search(self, query: str, top_k: int = 10, metadata_filter: Optional[dict] = None) -> list[VectorSearchHit]:
        if self._matrix is None or self._matrix.shape[0] == 0 or not self.backend.is_fitted:
            return []
        query_vec = self.backend.transform([query])
        if query_vec.shape[1] != self._matrix.shape[1]:
            return []
        sims = cosine_similarity(query_vec, self._matrix)[0]
        ranked = np.argsort(-sims)
        hits: list[VectorSearchHit] = []
        for idx in ranked:
            if sims[idx] <= 0:
                continue
            meta = self._metadata[idx]
            if metadata_filter and not all(meta.get(k) == v for k, v in metadata_filter.items()):
                continue
            hits.append(VectorSearchHit(doc_id=self._doc_ids[idx], score=float(sims[idx]), metadata=meta))
            if len(hits) >= top_k:
                break
        return hits

    def similar_to_doc(self, doc_id: str, top_k: int = 10) -> list[VectorSearchHit]:
        if doc_id not in self._doc_ids or self._matrix is None:
            return []
        idx = self._doc_ids.index(doc_id)
        sims = cosine_similarity(self._matrix[idx : idx + 1], self._matrix)[0]
        ranked = np.argsort(-sims)
        hits = []
        for i in ranked:
            if self._doc_ids[i] == doc_id:
                continue
            if sims[i] <= 0:
                continue
            hits.append(VectorSearchHit(doc_id=self._doc_ids[i], score=float(sims[i]), metadata=self._metadata[i]))
            if len(hits) >= top_k:
                break
        return hits

    def size(self) -> int:
        return len(self._doc_ids)
