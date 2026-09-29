"""
Synthetic Security Universe Generator (Synthetic Connector).

Generates deterministic, seeded synthetic hosts/processes/users/services/
containers/network/authentication/configuration events for testing,
benchmarking, and demoing reconstruction — never real telemetry, never a
real target. This module has no capability to send, execute, or exploit
anything; it only ever produces in-memory `CanonicalSecurityEvent` objects
tagged with `ProvenanceSource.SYNTHETIC` so downstream consumers can always
tell synthetic data apart from real observations.

Use cases: populating a demo/dev environment, the Reconstruction Benchmark
Lab, and regression-testing Episode/Causal/Divergence engines against
known, reproducible "ground truth" scenarios.
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from phantom_memory.core.models import (
    CanonicalSecurityEvent,
    EventCategory,
    ProvenanceMetadata,
    ProvenanceSource,
    TimestampInfo,
)
from phantom_memory.ingestion.connectors.base import BaseConnector

_PROCESS_NAMES = ["bash", "sshd", "curl", "python3", "systemd", "cron", "nginx", "postgres"]
_SCENARIOS = ("benign_baseline", "process_injection_like", "new_network_relationship",
              "identity_drift", "configuration_change_chain", "service_failure_recovery")


class SyntheticSecurityUniverseGenerator(BaseConnector):
    """A connector-shaped synthetic data generator: same `pull()` interface
    as any real connector, so it can be swapped in wherever a connector is
    expected (ingestion pipeline, CLI `benchmark`, integration tests)."""

    required_permissions: tuple[str, ...] = ()  # synthetic data needs no external access

    def __init__(self, connector_id: str = "synthetic-universe", *, seed: int = 42,
                 scenario: str = "benign_baseline", host_count: int = 5, **kwargs):
        self.seed = seed
        self.scenario = scenario if scenario in _SCENARIOS else "benign_baseline"
        self.host_count = host_count
        self._rng = random.Random(seed)
        self._emitted = 0
        super().__init__(connector_id, **kwargs)

    def authenticate(self) -> bool:
        return True  # nothing to authenticate against; purely local generation

    def fetch_batch(
        self, cursor: Optional[str], batch_size: int
    ) -> tuple[list[CanonicalSecurityEvent], Optional[str]]:
        start_index = int(cursor) if cursor else 0
        base_time = datetime.now(timezone.utc)
        events = [
            self._generate_event(start_index + i, base_time) for i in range(batch_size)
        ]
        new_cursor = str(start_index + batch_size)
        return events, new_cursor

    def _generate_event(self, index: int, base_time: datetime) -> CanonicalSecurityEvent:
        rng = self._rng
        host_id = f"host-{index % self.host_count:02d}"
        t = base_time + timedelta(seconds=index)

        if self.scenario == "process_injection_like" and index % 37 == 0:
            category, etype = EventCategory.PROCESS, "process.exec.anomalous"
            payload = {"process_name": "unlisted_binary", "parent": "explorer_like_host_process"}
        elif self.scenario == "new_network_relationship" and index % 29 == 0:
            category, etype = EventCategory.NETWORK_CONNECTION, "network.connect"
            payload = {"source_endpoint": f"10.0.{index%255}.5:{40000+index%1000}",
                       "destination_endpoint": f"198.51.100.{index%255}:443"}
        elif self.scenario == "identity_drift" and index % 41 == 0:
            category, etype = EventCategory.AUTHENTICATION, "authentication.login"
            payload = {"auth_method": "password"}
        elif self.scenario == "configuration_change_chain" and index % 23 == 0:
            category, etype = EventCategory.CONFIGURATION_CHANGE, "configuration.update"
            payload = {"config_key": f"policy.rule.{index%10}", "old_value": "allow", "new_value": "deny"}
        elif self.scenario == "service_failure_recovery" and index % 31 == 0:
            category, etype = EventCategory.SERVICE_LIFECYCLE, "service.restart"
            payload = {"service_name": f"svc-{index%7}"}
        else:
            category = rng.choice([EventCategory.PROCESS, EventCategory.NETWORK_CONNECTION, EventCategory.AUTHENTICATION])
            etype = {
                EventCategory.PROCESS: "process.exec",
                EventCategory.NETWORK_CONNECTION: "network.connect",
                EventCategory.AUTHENTICATION: "authentication.login",
            }[category]
            payload = {"process_name": rng.choice(_PROCESS_NAMES)}

        actor = f"ent_process_synthetic_{index % 50}"
        target = f"ent_process_synthetic_{(index + 1) % 50}"

        return CanonicalSecurityEvent(
            event_id=f"evt_synth_{uuid.uuid4().hex}",
            event_type=etype,
            event_category=category,
            timestamps=TimestampInfo(event_time=t, receive_time=t),
            source=ProvenanceMetadata(source=ProvenanceSource.SYNTHETIC, collector_id=self.connector_id),
            actor_entity_id=actor,
            target_entity_id=target,
            host_id=host_id,
            user_identity=f"synthetic_user_{index % 10}",
            payload_metadata=payload,
            confidence=1.0,
        )
