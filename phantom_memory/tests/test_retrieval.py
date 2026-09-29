from __future__ import annotations

from phantom_memory.retrieval.vector_index import VectorMemoryIndex


def test_vector_index_search_returns_relevant_doc():
    idx = VectorMemoryIndex()
    idx.upsert("doc1", "suspicious process spawned a reverse shell over tcp", {"type": "episode"})
    idx.upsert("doc2", "user logged in with normal password authentication", {"type": "episode"})
    idx.upsert("doc3", "scheduled backup job ran successfully", {"type": "episode"})

    hits = idx.search("reverse shell process spawn", top_k=2)
    assert hits
    assert hits[0].doc_id == "doc1"


def test_vector_index_similar_to_doc():
    idx = VectorMemoryIndex()
    idx.upsert("doc1", "malicious process spawned network connection to unknown host")
    idx.upsert("doc2", "malicious process spawned outbound network connection")
    idx.upsert("doc3", "routine scheduled maintenance job completed")

    hits = idx.similar_to_doc("doc1", top_k=2)
    doc_ids = [h.doc_id for h in hits]
    assert "doc2" in doc_ids


def test_vector_index_empty_search_returns_nothing():
    idx = VectorMemoryIndex()
    assert idx.search("anything") == []
