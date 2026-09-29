from __future__ import annotations

import json
from pathlib import Path

import pytest

from phantom_memory.ingestion.connectors.base import ConnectorAuthError
from phantom_memory.ingestion.connectors.file_connector import FileConnector
from phantom_memory.ingestion.connectors.synthetic_connector import SyntheticSecurityUniverseGenerator


def test_file_connector_requires_permission(tmp_path):
    f = tmp_path / "events.ndjson"
    f.write_text("")
    with pytest.raises(ConnectorAuthError):
        FileConnector("f1", f, checkpoint_dir=tmp_path / "ck")


def test_file_connector_incremental_sync(tmp_path):
    f = tmp_path / "events.ndjson"
    records = [
        {
            "event_id": f"evt_{i}",
            "event_type": "process.exec",
            "event_category": "process",
            "timestamps": {"event_time": "2026-01-01T00:00:00Z"},
            "source": {"source": "custom_connector"},
            "actor_entity_id": f"a{i}",
            "target_entity_id": f"b{i}",
        }
        for i in range(5)
    ]
    f.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    conn = FileConnector("f1", f, checkpoint_dir=tmp_path / "ck", granted_permissions=["read_local_file"])
    batch1 = conn.pull(batch_size=3)
    assert len(batch1) == 3
    batch2 = conn.pull(batch_size=3)
    assert len(batch2) == 2
    batch3 = conn.pull(batch_size=3)
    assert len(batch3) == 0


def test_file_connector_checkpoint_survives_restart(tmp_path):
    f = tmp_path / "events.ndjson"
    records = [
        {
            "event_id": f"evt_{i}",
            "event_type": "process.exec",
            "event_category": "process",
            "timestamps": {"event_time": "2026-01-01T00:00:00Z"},
            "source": {"source": "custom_connector"},
            "actor_entity_id": f"a{i}",
            "target_entity_id": f"b{i}",
        }
        for i in range(3)
    ]
    f.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    ck_dir = tmp_path / "ck"

    conn1 = FileConnector("f1", f, checkpoint_dir=ck_dir, granted_permissions=["read_local_file"])
    conn1.pull(batch_size=10)
    saved_cursor = conn1.checkpoint.cursor

    conn2 = FileConnector("f1", f, checkpoint_dir=ck_dir, granted_permissions=["read_local_file"])
    assert conn2.checkpoint.cursor == saved_cursor
    assert conn2.pull(batch_size=10) == []


def test_synthetic_generator_is_deterministic_for_same_seed(tmp_path):
    gen_a = SyntheticSecurityUniverseGenerator(
        "synth-a", seed=123, checkpoint_dir=tmp_path / "ck_a"
    )
    gen_b = SyntheticSecurityUniverseGenerator(
        "synth-b", seed=123, checkpoint_dir=tmp_path / "ck_b"
    )
    batch_a = gen_a.pull(batch_size=20)
    batch_b = gen_b.pull(batch_size=20)
    assert [e.event_type for e in batch_a] == [e.event_type for e in batch_b]
    assert [e.host_id for e in batch_a] == [e.host_id for e in batch_b]


def test_synthetic_generator_tags_synthetic_provenance(tmp_path):
    gen = SyntheticSecurityUniverseGenerator("synth-c", checkpoint_dir=tmp_path / "ck")
    batch = gen.pull(batch_size=10)
    assert all(e.source.source.value == "synthetic" for e in batch)
