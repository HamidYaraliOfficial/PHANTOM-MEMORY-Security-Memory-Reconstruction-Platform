from __future__ import annotations

from datetime import datetime, timezone

from phantom_memory.core.models import (
    CanonicalSecurityEvent,
    EventCategory,
    ProvenanceMetadata,
    ProvenanceSource,
    TimestampInfo,
)


def test_event_entity_ids_include_actor_and_target():
    event = CanonicalSecurityEvent(
        event_id="evt_1",
        event_type="process.exec",
        event_category=EventCategory.PROCESS,
        timestamps=TimestampInfo(event_time=datetime.now(timezone.utc)),
        source=ProvenanceMetadata(source=ProvenanceSource.EBPF_SENSOR),
        actor_entity_id="ent_process_a",
        target_entity_id="ent_process_b",
    )
    assert "ent_process_a" in event.entity_ids
    assert "ent_process_b" in event.entity_ids


def test_content_hash_deterministic_for_identical_content():
    ts = datetime.now(timezone.utc)
    kwargs = dict(
        event_type="process.exec",
        event_category=EventCategory.PROCESS,
        timestamps=TimestampInfo(event_time=ts),
        source=ProvenanceMetadata(source=ProvenanceSource.EBPF_SENSOR),
        actor_entity_id="ent_process_a",
        target_entity_id="ent_process_b",
        host_id="host-1",
    )
    e1 = CanonicalSecurityEvent(event_id="evt_1", **kwargs)
    e2 = CanonicalSecurityEvent(event_id="evt_2", **kwargs)  # different event_id, same content
    assert e1.compute_content_hash() == e2.compute_content_hash()


def test_content_hash_changes_with_payload():
    ts = datetime.now(timezone.utc)
    base_kwargs = dict(
        event_id="evt_1",
        event_type="process.exec",
        event_category=EventCategory.PROCESS,
        timestamps=TimestampInfo(event_time=ts),
        source=ProvenanceMetadata(source=ProvenanceSource.EBPF_SENSOR),
        actor_entity_id="ent_process_a",
        target_entity_id="ent_process_b",
    )
    e1 = CanonicalSecurityEvent(**base_kwargs, payload_metadata={"process_name": "bash"})
    e2 = CanonicalSecurityEvent(**base_kwargs, payload_metadata={"process_name": "curl"})
    assert e1.compute_content_hash() != e2.compute_content_hash()


def test_finalize_sets_content_hash_once():
    event = CanonicalSecurityEvent(
        event_id="evt_1",
        event_type="process.exec",
        event_category=EventCategory.PROCESS,
        timestamps=TimestampInfo(event_time=datetime.now(timezone.utc)),
        source=ProvenanceMetadata(source=ProvenanceSource.EBPF_SENSOR),
    )
    assert event.content_hash is None
    event.finalize()
    first_hash = event.content_hash
    event.finalize()
    assert event.content_hash == first_hash
