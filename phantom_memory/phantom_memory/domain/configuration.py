"""
Configuration Memory Engine.

Versions configuration changes, shows before/after values, and relates a
configuration change to nearby episodes/incidents — without ever assuming
the correlation it reports is proof of causation.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class ConfigurationChange:
    config_key: str
    changed_at: datetime
    old_value: str | None
    new_value: str | None
    changed_by: str | None
    event_id: str
    environment: str | None


class ConfigurationMemoryEngine:
    def history(self, events: list[CanonicalSecurityEvent], config_key: str | None = None) -> list[ConfigurationChange]:
        relevant = [e for e in events if e.event_category.value == "configuration_change"]
        if config_key:
            relevant = [e for e in relevant if e.payload_metadata.get("config_key") == config_key]
        relevant.sort(key=lambda e: e.timestamps.event_time)
        return [
            ConfigurationChange(
                config_key=e.payload_metadata.get("config_key", "unknown"),
                changed_at=e.timestamps.event_time,
                old_value=e.payload_metadata.get("old_value"),
                new_value=e.payload_metadata.get("new_value"),
                changed_by=e.user_identity,
                event_id=e.event_id,
                environment=e.environment,
            )
            for e in relevant
        ]

    def near_incidents(
        self, changes: list[ConfigurationChange], incident_times: list[datetime], window: timedelta = timedelta(hours=1)
    ) -> list[dict]:
        """Flags configuration changes that fall within `window` of a known
        incident time — reported strictly as temporal proximity, with an
        explicit caveat, never as a causal claim."""
        results = []
        for change in changes:
            nearby = [t for t in incident_times if abs((t - change.changed_at).total_seconds()) <= window.total_seconds()]
            if nearby:
                results.append({
                    "config_key": change.config_key,
                    "changed_at": change.changed_at.isoformat(),
                    "nearby_incident_times": [t.isoformat() for t in nearby],
                    "caveat": "Temporal proximity only — not established as a cause of the incident(s).",
                })
        return results


class ConfigurationDiffExplorer:
    def diff_at_points(
        self, changes: list[ConfigurationChange], point_a: datetime, point_b: datetime
    ) -> dict[str, dict]:
        """Effective config value per key at two points in time, and what
        changed between them."""
        def value_at(t: datetime) -> dict[str, str | None]:
            values: dict[str, str | None] = {}
            for c in sorted(changes, key=lambda x: x.changed_at):
                if c.changed_at <= t:
                    values[c.config_key] = c.new_value
            return values

        before = value_at(point_a)
        after = value_at(point_b)
        keys = set(before) | set(after)
        diff = {}
        for k in keys:
            if before.get(k) != after.get(k):
                diff[k] = {"before": before.get(k), "after": after.get(k)}
        return diff
