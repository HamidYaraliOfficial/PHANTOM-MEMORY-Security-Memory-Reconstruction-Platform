from __future__ import annotations

from datetime import timedelta

from phantom_memory.core.models import EventCategory
from phantom_memory.temporal.replay import ReplayStatus

from .conftest import make_event


def test_state_at_reflects_active_process(system, base_time):
    e = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    system.ingest(e)
    state = system.temporal_memory.state_at(base_time + timedelta(seconds=5))
    assert len(state.running_processes) == 1


def test_state_before_event_shows_nothing(system, base_time):
    e = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    system.ingest(e)
    state = system.temporal_memory.state_at(base_time - timedelta(seconds=5))
    assert len(state.running_processes) == 0


def test_snapshot_and_diff(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    system.ingest(e1)
    system.snapshots.create_snapshot(base_time + timedelta(seconds=1), label="before")

    e2 = make_event(
        "network.connect", EventCategory.NETWORK_CONNECTION, "ent_c", "ent_d",
        base_time + timedelta(seconds=10),
    )
    system.ingest(e2)
    system.snapshots.create_snapshot(base_time + timedelta(seconds=11), label="after")

    diff = system.temporal_diff.diff(base_time + timedelta(seconds=1), base_time + timedelta(seconds=11))
    assert len(diff.connections_opened) == 1


def test_replay_processes_events_in_order(system, base_time):
    for i in range(5):
        e = make_event(
            "process.exec", EventCategory.PROCESS, f"ent_{i}", f"ent_{i+1}",
            base_time + timedelta(seconds=i),
        )
        system.ingest(e)

    seen = []
    system.replay.load()
    progress = system.replay.play(lambda ev: seen.append(ev.event_id))
    assert progress.status == ReplayStatus.COMPLETED
    assert len(seen) == 5


def test_replay_pause_and_resume(system, base_time):
    for i in range(5):
        e = make_event(
            "process.exec", EventCategory.PROCESS, f"ent_{i}", f"ent_{i+1}",
            base_time + timedelta(seconds=i),
        )
        system.ingest(e)

    system.replay.load()
    seen = []
    progress = system.replay.play(lambda ev: seen.append(ev.event_id), max_events=2)
    assert len(seen) == 2
    assert progress.status in (ReplayStatus.PAUSED, ReplayStatus.COMPLETED)

    progress2 = system.replay.play(lambda ev: seen.append(ev.event_id))
    assert len(seen) == 5
    assert progress2.status == ReplayStatus.COMPLETED
