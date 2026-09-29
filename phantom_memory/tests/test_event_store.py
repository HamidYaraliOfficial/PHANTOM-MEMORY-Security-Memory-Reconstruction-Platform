from __future__ import annotations

import pytest

from phantom_memory.core.event_store import EventStore, ImmutableEventError
from phantom_memory.core.models import EventCategory

from .conftest import make_event


def test_write_and_get_normalized_event(tmp_data_dir, base_time):
    store = EventStore(tmp_data_dir / "events.db")
    event = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    stored = store.write_normalized(event)
    assert stored.content_hash is not None

    fetched = store.get(event.event_id)
    assert fetched is not None
    assert fetched.event_id == event.event_id


def test_normalized_events_are_immutable(tmp_data_dir, base_time):
    store = EventStore(tmp_data_dir / "events.db")
    event = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    store.write_normalized(event)
    with pytest.raises(ImmutableEventError):
        store.write_normalized(event)


def test_query_filters_by_time_range(tmp_data_dir, base_time):
    from datetime import timedelta

    store = EventStore(tmp_data_dir / "events.db")
    for i in range(5):
        e = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time + timedelta(minutes=i))
        store.write_normalized(e)

    results = store.query(start_time=base_time + timedelta(minutes=2), end_time=base_time + timedelta(minutes=3))
    assert len(results) == 2


def test_derived_artifacts_are_recomputable(tmp_data_dir):
    store = EventStore(tmp_data_dir / "events.db")
    store.write_derived("art_1", "episode", ["evt_1"], {"foo": "bar"}, "v1")
    assert len(store.get_derived("episode")) == 1
    purged = store.purge_derived("episode")
    assert purged == 1
    assert len(store.get_derived("episode")) == 0


def test_hash_chain_extends_per_host(tmp_data_dir, base_time):
    from datetime import timedelta

    store = EventStore(tmp_data_dir / "events.db")
    for i in range(3):
        e = make_event(
            "process.exec", EventCategory.PROCESS, "ent_a", "ent_b",
            base_time + timedelta(seconds=i), host_id="host-x",
        )
        store.write_normalized(e)
    assert store.verify_hash_chain_length("host-x") == 3
