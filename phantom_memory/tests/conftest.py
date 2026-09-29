from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from phantom_memory.core.models import (
    CanonicalSecurityEvent,
    EventCategory,
    ProvenanceMetadata,
    ProvenanceSource,
    TimestampInfo,
)
from phantom_memory.system import PhantomMemorySystem


@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "phantom_data"
    d.mkdir()
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def system(tmp_data_dir: Path) -> PhantomMemorySystem:
    return PhantomMemorySystem(data_dir=str(tmp_data_dir))


def make_event(
    event_type: str,
    category: EventCategory,
    actor: str,
    target: str,
    event_time: datetime,
    *,
    host_id: str = "host-01",
    user_identity: str | None = None,
    payload: dict | None = None,
    source: ProvenanceSource = ProvenanceSource.EBPF_SENSOR,
    correlation_id: str | None = None,
) -> CanonicalSecurityEvent:
    return CanonicalSecurityEvent(
        event_id=f"evt_{uuid.uuid4().hex}",
        event_type=event_type,
        event_category=category,
        timestamps=TimestampInfo(event_time=event_time, receive_time=event_time),
        source=ProvenanceMetadata(source=source),
        actor_entity_id=actor,
        target_entity_id=target,
        host_id=host_id,
        user_identity=user_identity,
        payload_metadata=payload or {},
        correlation_id=correlation_id,
    )


@pytest.fixture
def base_time() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
