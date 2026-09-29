"""
Memory Confidence Engine.

Computes an explainable confidence score for an Episode or Relationship
from: source reliability, event density, temporal consistency, graph
consistency, historical agreement, and data quality (contradiction rate /
telemetry gaps). Used by the UI to show *why* something is trusted or not,
and by retention/decay logic to decide what to keep at full fidelity.
"""
from __future__ import annotations

from dataclasses import dataclass

from phantom_memory.core.models import CanonicalSecurityEvent, Episode

_SOURCE_RELIABILITY = {
    "ebpf_sensor": 0.95,
    "opentelemetry": 0.85,
    "journald_syslog": 0.75,
    "api_log": 0.8,
    "auth_log": 0.9,
    "cloud_audit": 0.9,
    "kubernetes_event": 0.85,
    "application_event": 0.7,
    "custom_connector": 0.6,
    "derived_engine": 0.5,
    "synthetic": 1.0,
}


@dataclass
class ConfidenceBreakdown:
    source_reliability: float
    event_density: float
    temporal_consistency: float
    graph_consistency: float
    historical_agreement: float
    data_quality: float
    final: float

    def as_dict(self) -> dict:
        return self.__dict__


class MemoryConfidenceEngine:
    WEIGHTS = {
        "source_reliability": 0.25,
        "event_density": 0.15,
        "temporal_consistency": 0.15,
        "graph_consistency": 0.15,
        "historical_agreement": 0.15,
        "data_quality": 0.15,
    }

    def score_episode(
        self,
        episode: Episode,
        events: list[CanonicalSecurityEvent],
        *,
        contradiction_count: int = 0,
        visibility_gap_ratio: float = 0.0,
        historical_pattern_matches: int = 0,
    ) -> ConfidenceBreakdown:
        if not events:
            return ConfidenceBreakdown(0, 0, 0, 0, 0, 0, 0.0)

        source_rel = sum(_SOURCE_RELIABILITY.get(e.source.source.value, 0.5) for e in events) / len(events)
        density = min(1.0, len(events) / max(1, len(episode.entity_ids)) / 4.0)

        sorted_events = sorted(events, key=lambda e: e.timestamps.event_time)
        out_of_order = sum(
            1 for a, b in zip(sorted_events, sorted_events[1:]) if b.timestamps.event_time < a.timestamps.event_time
        )
        temporal_consistency = max(0.0, 1.0 - (out_of_order / max(1, len(sorted_events) - 1)))

        graph_consistency = max(0.0, 1.0 - min(1.0, contradiction_count / 5.0))
        historical_agreement = min(1.0, historical_pattern_matches / 3.0)
        data_quality = max(0.0, 1.0 - visibility_gap_ratio)

        w = self.WEIGHTS
        final = (
            w["source_reliability"] * source_rel
            + w["event_density"] * density
            + w["temporal_consistency"] * temporal_consistency
            + w["graph_consistency"] * graph_consistency
            + w["historical_agreement"] * historical_agreement
            + w["data_quality"] * data_quality
        )
        return ConfidenceBreakdown(
            source_reliability=round(source_rel, 4),
            event_density=round(density, 4),
            temporal_consistency=round(temporal_consistency, 4),
            graph_consistency=round(graph_consistency, 4),
            historical_agreement=round(historical_agreement, 4),
            data_quality=round(data_quality, 4),
            final=round(max(0.0, min(1.0, final)), 4),
        )
