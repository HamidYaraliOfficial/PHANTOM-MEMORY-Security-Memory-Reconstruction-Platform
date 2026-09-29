"""
First-Divergence Detection Engine.

Given an incident timeline and a behavioral baseline, finds the earliest
moment the system's behavior departed from what was expected: the first
unexpected process, the first new network connection, the first identity
drift, the first configuration change, the first boundary (segmentation/
permission) change, and the first missing event (an expected heartbeat or
control signal that never arrived). Every finding is returned together with
the events immediately before and after it, so an analyst always sees the
divergence in context rather than as an isolated data point.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class BehavioralBaseline:
    """A simple, explicit, inspectable baseline. In production this would be
    learned/maintained by the Behavioral Memory Baseline subsystem; here it
    is supplied (or built with `from_events`) so divergence detection stays
    fully deterministic and auditable."""
    known_process_names: set[str] = field(default_factory=set)
    known_connection_pairs: set[tuple[str, str]] = field(default_factory=set)
    known_identities: set[str] = field(default_factory=set)
    known_config_keys: set[str] = field(default_factory=set)
    known_boundaries: set[str] = field(default_factory=set)
    expected_event_types: set[str] = field(default_factory=set)
    expected_interval: timedelta = timedelta(minutes=10)

    @classmethod
    def from_events(cls, events: list[CanonicalSecurityEvent]) -> "BehavioralBaseline":
        baseline = cls()
        for e in events:
            name = e.payload_metadata.get("process_name")
            if name:
                baseline.known_process_names.add(name)
            src = e.payload_metadata.get("source_endpoint")
            dst = e.payload_metadata.get("destination_endpoint")
            if src and dst:
                baseline.known_connection_pairs.add((src, dst))
            if e.user_identity:
                baseline.known_identities.add(e.user_identity)
            cfg_key = e.payload_metadata.get("config_key")
            if cfg_key:
                baseline.known_config_keys.add(cfg_key)
            boundary = e.payload_metadata.get("network_boundary")
            if boundary:
                baseline.known_boundaries.add(boundary)
            baseline.expected_event_types.add(e.event_type)
        return baseline


@dataclass
class DivergenceFinding:
    kind: str
    event_id: str
    at_time: str
    description: str
    context_before: list[str]
    context_after: list[str]


class FirstDivergenceEngine:
    def find(
        self, timeline: list[CanonicalSecurityEvent], baseline: BehavioralBaseline, context_window: int = 2
    ) -> dict[str, Optional[DivergenceFinding]]:
        timeline = sorted(timeline, key=lambda e: e.timestamps.event_time)
        findings: dict[str, Optional[DivergenceFinding]] = {
            "first_unexpected_process": None,
            "first_new_connection": None,
            "first_identity_drift": None,
            "first_configuration_change": None,
            "first_boundary_change": None,
            "first_missing_event": None,
        }

        for i, e in enumerate(timeline):
            name = e.payload_metadata.get("process_name")
            if findings["first_unexpected_process"] is None and name and name not in baseline.known_process_names:
                findings["first_unexpected_process"] = self._make(
                    "first_unexpected_process", e, timeline, i, context_window,
                    f"process '{name}' not present in baseline",
                )

            src = e.payload_metadata.get("source_endpoint")
            dst = e.payload_metadata.get("destination_endpoint")
            if (
                findings["first_new_connection"] is None
                and src and dst
                and (src, dst) not in baseline.known_connection_pairs
            ):
                findings["first_new_connection"] = self._make(
                    "first_new_connection", e, timeline, i, context_window,
                    f"connection {src} -> {dst} not present in baseline",
                )

            if (
                findings["first_identity_drift"] is None
                and e.user_identity
                and e.user_identity not in baseline.known_identities
            ):
                findings["first_identity_drift"] = self._make(
                    "first_identity_drift", e, timeline, i, context_window,
                    f"identity '{e.user_identity}' not present in baseline",
                )

            cfg_key = e.payload_metadata.get("config_key")
            if findings["first_configuration_change"] is None and cfg_key and cfg_key not in baseline.known_config_keys:
                findings["first_configuration_change"] = self._make(
                    "first_configuration_change", e, timeline, i, context_window,
                    f"configuration key '{cfg_key}' changed outside baseline",
                )

            boundary = e.payload_metadata.get("network_boundary")
            if findings["first_boundary_change"] is None and boundary and boundary not in baseline.known_boundaries:
                findings["first_boundary_change"] = self._make(
                    "first_boundary_change", e, timeline, i, context_window,
                    f"boundary/segment '{boundary}' not present in baseline",
                )

        findings["first_missing_event"] = self._find_missing_event(timeline, baseline, context_window)
        return findings

    def _make(self, kind, event, timeline, i, window, description) -> DivergenceFinding:
        before = [ev.event_id for ev in timeline[max(0, i - window): i]]
        after = [ev.event_id for ev in timeline[i + 1: i + 1 + window]]
        return DivergenceFinding(
            kind=kind,
            event_id=event.event_id,
            at_time=event.timestamps.event_time.isoformat(),
            description=description,
            context_before=before,
            context_after=after,
        )

    def _find_missing_event(
        self, timeline: list[CanonicalSecurityEvent], baseline: BehavioralBaseline, window: int
    ) -> Optional[DivergenceFinding]:
        if not baseline.expected_event_types or len(timeline) < 2:
            return None
        for i in range(len(timeline) - 1):
            gap = timeline[i + 1].timestamps.event_time - timeline[i].timestamps.event_time
            if gap > baseline.expected_interval * 2:
                return self._make(
                    "first_missing_event", timeline[i], timeline, i, window,
                    f"gap of {gap} exceeds 2x expected interval "
                    f"({baseline.expected_interval}) — telemetry may be missing here",
                )
        return None

    def overall_first_divergence(
        self, findings: dict[str, Optional[DivergenceFinding]]
    ) -> Optional[DivergenceFinding]:
        candidates = [f for f in findings.values() if f is not None]
        if not candidates:
            return None
        return min(candidates, key=lambda f: f.at_time)
