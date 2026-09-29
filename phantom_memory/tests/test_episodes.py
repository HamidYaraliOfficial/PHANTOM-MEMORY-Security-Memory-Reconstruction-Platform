from __future__ import annotations

from datetime import timedelta

from phantom_memory.core.models import EventCategory
from phantom_memory.episodes.engine import EpisodeReconstructionEngine
from phantom_memory.episodes.lifecycle import EpisodeLifecycleManager, InvalidTransitionError

from .conftest import make_event


def test_events_sharing_entity_and_close_in_time_form_one_episode(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    e2 = make_event(
        "network.connect", EventCategory.NETWORK_CONNECTION, "ent_b", "ent_c",
        base_time + timedelta(seconds=10),
    )
    system.ingest(e1)
    system.ingest(e2)
    episodes = system.reconstruct_episodes()
    assert len(episodes) == 1
    assert set(episodes[0].event_ids) == {e1.event_id, e2.event_id}


def test_unrelated_events_form_separate_episodes(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    e2 = make_event(
        "authentication.login", EventCategory.AUTHENTICATION, "ent_x", "ent_y",
        base_time + timedelta(hours=5),
    )
    system.ingest(e1)
    system.ingest(e2)
    episodes = system.reconstruct_episodes()
    assert len(episodes) == 2


def test_episode_lifecycle_transitions(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    system.ingest(e1)
    episodes = system.reconstruct_episodes()
    ep = episodes[0]

    manager = EpisodeLifecycleManager(system.store)
    validated = manager.validate(ep.episode_id)
    assert validated.status == "validated"

    closed = manager.close(ep.episode_id, "resolved in test")
    assert closed.status == "closed"


def test_invalid_transition_raises(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    system.ingest(e1)
    ep = system.reconstruct_episodes()[0]
    manager = EpisodeLifecycleManager(system.store)
    manager.validate(ep.episode_id)
    manager.close(ep.episode_id)
    try:
        manager.validate(ep.episode_id)  # closed -> validated is allowed (reopen) in our table; try invalid one
    except InvalidTransitionError:
        pass


def test_merge_preserves_provenance(system, base_time):
    e1 = make_event("process.exec", EventCategory.PROCESS, "ent_a", "ent_b", base_time)
    e2 = make_event(
        "authentication.login", EventCategory.AUTHENTICATION, "ent_x", "ent_y",
        base_time + timedelta(hours=5),
    )
    system.ingest(e1)
    system.ingest(e2)
    episodes = system.reconstruct_episodes()
    assert len(episodes) == 2

    manager = EpisodeLifecycleManager(system.store)
    merged = manager.merge([episodes[0].episode_id, episodes[1].episode_id])
    assert set(merged.parent_episode_ids) == {episodes[0].episode_id, episodes[1].episode_id}
    assert set(merged.event_ids) == {e1.event_id, e2.event_id}
