from __future__ import annotations

from datetime import timedelta

from phantom_memory.core.models import EdgeType, EntityType
from phantom_memory.graph.entity_resolution import EntityResolutionEngine
from phantom_memory.graph.memory_graph import SecurityMemoryGraph
from phantom_memory.graph.search import GraphQueryOptions, GraphSearchEngine


def test_upsert_entity_dedupes_by_natural_key(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    e1 = g.upsert_entity(EntityType.PROCESS, "bash", natural_key="host1:pid1", at_time=base_time)
    e2 = g.upsert_entity(
        EntityType.PROCESS, "bash", natural_key="host1:pid1", at_time=base_time + timedelta(minutes=5)
    )
    assert e1.entity_id == e2.entity_id
    fetched = g.get_entity(e1.entity_id)
    assert fetched.last_seen >= fetched.first_seen


def test_add_edge_and_edges_valid_at(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    a = g.upsert_entity(EntityType.PROCESS, "bash", at_time=base_time)
    b = g.upsert_entity(EntityType.NETWORK_ENDPOINT, "10.0.0.1:443", at_time=base_time)
    g.add_edge(
        EdgeType.CONNECTED_TO, a.entity_id, b.entity_id,
        valid_from=base_time, valid_to=base_time + timedelta(minutes=10), confidence=0.9,
    )
    valid_mid = g.edges_valid_at(base_time + timedelta(minutes=5), EdgeType.CONNECTED_TO)
    valid_after = g.edges_valid_at(base_time + timedelta(minutes=20), EdgeType.CONNECTED_TO)
    assert len(valid_mid) == 1
    assert len(valid_after) == 0


def test_graph_search_neighbors(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    a = g.upsert_entity(EntityType.PROCESS, "a", at_time=base_time)
    b = g.upsert_entity(EntityType.PROCESS, "b", at_time=base_time)
    g.add_edge(EdgeType.SPAWNED, a.entity_id, b.entity_id, valid_from=base_time, confidence=0.8)

    search = GraphSearchEngine(g)
    neighbors = search.neighbors(a.entity_id)
    assert any(n["neighbor"] == b.entity_id for n in neighbors)


def test_graph_search_multi_hop(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    a = g.upsert_entity(EntityType.PROCESS, "a", at_time=base_time)
    b = g.upsert_entity(EntityType.PROCESS, "b", at_time=base_time)
    c = g.upsert_entity(EntityType.PROCESS, "c", at_time=base_time)
    g.add_edge(EdgeType.SPAWNED, a.entity_id, b.entity_id, valid_from=base_time)
    g.add_edge(EdgeType.SPAWNED, b.entity_id, c.entity_id, valid_from=base_time)

    search = GraphSearchEngine(g)
    layers = search.multi_hop(a.entity_id, hops=2)
    assert c.entity_id in layers[2]


def test_shortest_paths(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    a = g.upsert_entity(EntityType.PROCESS, "a", at_time=base_time)
    b = g.upsert_entity(EntityType.PROCESS, "b", at_time=base_time)
    c = g.upsert_entity(EntityType.PROCESS, "c", at_time=base_time)
    g.add_edge(EdgeType.SPAWNED, a.entity_id, b.entity_id, valid_from=base_time)
    g.add_edge(EdgeType.SPAWNED, b.entity_id, c.entity_id, valid_from=base_time)

    search = GraphSearchEngine(g)
    paths = search.shortest_paths(a.entity_id, c.entity_id)
    assert len(paths) >= 1
    assert paths[0].path[0] == a.entity_id
    assert paths[0].path[-1] == c.entity_id


def test_entity_merge_and_undo(tmp_data_dir, base_time):
    g = SecurityMemoryGraph(tmp_data_dir / "graph.db")
    a = g.upsert_entity(EntityType.USER, "jdoe", at_time=base_time)
    b = g.upsert_entity(EntityType.USER, "jane.doe", at_time=base_time)
    resolver = EntityResolutionEngine(g)
    candidates = resolver.find_candidates([a.entity_id, b.entity_id], threshold=0.0)
    assert candidates  # low threshold guarantees at least one candidate
    kept = resolver.apply_merge(candidates[0])
    merged_entity = g.get_entity(b.entity_id if kept == a.entity_id else a.entity_id)
    assert merged_entity.merged_into == kept
