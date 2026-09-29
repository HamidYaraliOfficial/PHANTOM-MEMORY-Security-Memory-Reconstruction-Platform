from __future__ import annotations

from datetime import timedelta

from phantom_memory.core.models import EventCategory

from .conftest import make_event


def test_full_incident_reconstruction_flow(system, base_time):
    # A small "incident": a process spawns curl, which connects out, and a
    # user authenticates around the same time on an unrelated resource.
    exec_event = make_event(
        "process.exec", EventCategory.PROCESS, "ent_process_bash", "ent_process_curl",
        base_time, payload={"process_name": "curl"},
    )
    connect_event = make_event(
        "network.connect", EventCategory.NETWORK_CONNECTION,
        "ent_process_curl", "ent_network_endpoint_external",
        base_time + timedelta(seconds=3),
        payload={"source_endpoint": "10.0.0.5:1234", "destination_endpoint": "203.0.113.9:443"},
    )
    auth_event = make_event(
        "authentication.login", EventCategory.AUTHENTICATION,
        "ent_user_alice", "ent_service_vpn",
        base_time + timedelta(hours=2), user_identity="alice",
    )

    for e in (exec_event, connect_event, auth_event):
        result = system.ingest(e)
        assert result.accepted

    assert system.store.count() == 3
    assert system.graph.node_count() >= 4

    episodes = system.reconstruct_episodes()
    assert len(episodes) == 2  # process+network group together, auth is separate

    process_episode = next(ep for ep in episodes if ep.episode_type == "process_execution_episode")
    assert set(process_episode.event_ids) == {exec_event.event_id, connect_event.event_id}

    # Case management ties it together
    case = system.cases.create("Outbound connection from spawned process", analyst="analyst1")
    system.cases.attach_episode(case.case_id, process_episode.episode_id)
    case = system.cases.get(case.case_id)
    assert process_episode.episode_id in case.episode_ids

    # Temporal state confirms the connection was active shortly after
    state = system.temporal_memory.state_at(base_time + timedelta(seconds=5))
    assert len(state.active_connections) == 1

    # Snapshot + diff across the incident window
    system.snapshots.create_snapshot(base_time - timedelta(seconds=1), label="pre-incident")
    system.snapshots.create_snapshot(base_time + timedelta(seconds=10), label="post-connect")
    diff = system.temporal_diff.diff(base_time - timedelta(seconds=1), base_time + timedelta(seconds=10))
    assert len(diff.processes_started) == 1
    assert len(diff.connections_opened) == 1
