"""
Temporal Diff Engine.

Compares two snapshots (or two arbitrary timestamps, by taking fresh
snapshots) and reports what changed: processes started/stopped, connections
opened/closed, users logged in/out, configuration entries added/removed,
and service dependency changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from phantom_memory.temporal.memory_engine import TemporalMemoryEngine


def _index_by_pair(items: list[dict], key_a: str, key_b: str) -> dict[tuple, dict]:
    return {(i.get(key_a), i.get(key_b)): i for i in items}


@dataclass
class TemporalDiff:
    from_time: str
    to_time: str
    processes_started: list[dict] = field(default_factory=list)
    processes_stopped: list[dict] = field(default_factory=list)
    connections_opened: list[dict] = field(default_factory=list)
    connections_closed: list[dict] = field(default_factory=list)
    users_authenticated: list[dict] = field(default_factory=list)
    users_deauthenticated: list[dict] = field(default_factory=list)
    configuration_added: list[dict] = field(default_factory=list)
    configuration_removed: list[dict] = field(default_factory=list)
    dependencies_added: list[dict] = field(default_factory=list)
    dependencies_removed: list[dict] = field(default_factory=list)


class TemporalDiffEngine:
    def __init__(self, temporal_engine: TemporalMemoryEngine):
        self.temporal = temporal_engine

    def diff(self, from_time: datetime, to_time: datetime) -> TemporalDiff:
        before = self.temporal.state_at(from_time)
        after = self.temporal.state_at(to_time)

        procs_before = _index_by_pair(before.running_processes, "actor", "process")
        procs_after = _index_by_pair(after.running_processes, "actor", "process")
        conns_before = _index_by_pair(before.active_connections, "from", "to")
        conns_after = _index_by_pair(after.active_connections, "from", "to")
        auth_before = _index_by_pair(before.authenticated_users, "user", "resource")
        auth_after = _index_by_pair(after.authenticated_users, "user", "resource")
        cfg_before = _index_by_pair(before.active_configuration, "entity", "scope")
        cfg_after = _index_by_pair(after.active_configuration, "entity", "scope")
        dep_before = _index_by_pair(before.service_communications, "service", "depends_on")
        dep_after = _index_by_pair(after.service_communications, "service", "depends_on")

        diff = TemporalDiff(from_time=from_time.isoformat(), to_time=to_time.isoformat())
        diff.processes_started = [v for k, v in procs_after.items() if k not in procs_before]
        diff.processes_stopped = [v for k, v in procs_before.items() if k not in procs_after]
        diff.connections_opened = [v for k, v in conns_after.items() if k not in conns_before]
        diff.connections_closed = [v for k, v in conns_before.items() if k not in conns_after]
        diff.users_authenticated = [v for k, v in auth_after.items() if k not in auth_before]
        diff.users_deauthenticated = [v for k, v in auth_before.items() if k not in auth_after]
        diff.configuration_added = [v for k, v in cfg_after.items() if k not in cfg_before]
        diff.configuration_removed = [v for k, v in cfg_before.items() if k not in cfg_after]
        diff.dependencies_added = [v for k, v in dep_after.items() if k not in dep_before]
        diff.dependencies_removed = [v for k, v in dep_before.items() if k not in dep_after]
        return diff
