"""
Evidence Completeness Engine & Visibility Gap Detector.

Shows how much evidence a reconstruction actually has versus what would be
expected for full coverage, and flags time ranges / hosts / services where
telemetry was insufficient. Critically, this module never lets a gap be
read as a conclusion ("no data" is reported as "no data", never silently
treated as "nothing happened").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class VisibilityGap:
    host_id: str | None
    start: str
    end: str
    duration_seconds: float
    note: str = "No telemetry observed in this interval — absence of evidence, not evidence of absence."


@dataclass
class CompletenessReport:
    expected_hosts: set[str]
    observed_hosts: set[str]
    missing_hosts: set[str]
    coverage_ratio: float
    gaps: list[VisibilityGap] = field(default_factory=list)
    total_gap_seconds: float = 0.0

    def as_dict(self) -> dict:
        return {
            "expected_hosts": sorted(self.expected_hosts),
            "observed_hosts": sorted(self.observed_hosts),
            "missing_hosts": sorted(self.missing_hosts),
            "coverage_ratio": round(self.coverage_ratio, 4),
            "gap_count": len(self.gaps),
            "total_gap_seconds": self.total_gap_seconds,
            "gaps": [g.__dict__ for g in self.gaps],
        }


class EvidenceCompletenessEngine:
    def evaluate(
        self,
        events: list[CanonicalSecurityEvent],
        expected_hosts: set[str],
        window_start: datetime,
        window_end: datetime,
        max_expected_gap: timedelta = timedelta(minutes=20),
    ) -> CompletenessReport:
        observed_hosts = {e.host_id for e in events if e.host_id}
        missing_hosts = expected_hosts - observed_hosts
        coverage = len(observed_hosts) / len(expected_hosts) if expected_hosts else 1.0

        gaps: list[VisibilityGap] = []
        by_host: dict[str, list[CanonicalSecurityEvent]] = {}
        for e in events:
            if e.host_id:
                by_host.setdefault(e.host_id, []).append(e)

        for host_id in expected_hosts:
            host_events = sorted(by_host.get(host_id, []), key=lambda e: e.timestamps.event_time)
            cursor = window_start
            for e in host_events:
                gap_len = (e.timestamps.event_time - cursor).total_seconds()
                if gap_len > max_expected_gap.total_seconds():
                    gaps.append(
                        VisibilityGap(
                            host_id=host_id,
                            start=cursor.isoformat(),
                            end=e.timestamps.event_time.isoformat(),
                            duration_seconds=gap_len,
                        )
                    )
                cursor = e.timestamps.event_time
            tail_gap = (window_end - cursor).total_seconds()
            if tail_gap > max_expected_gap.total_seconds():
                gaps.append(
                    VisibilityGap(
                        host_id=host_id,
                        start=cursor.isoformat(),
                        end=window_end.isoformat(),
                        duration_seconds=tail_gap,
                    )
                )
            if host_id not in by_host:
                gaps.append(
                    VisibilityGap(
                        host_id=host_id,
                        start=window_start.isoformat(),
                        end=window_end.isoformat(),
                        duration_seconds=(window_end - window_start).total_seconds(),
                        note="No events at all from this host in the requested window.",
                    )
                )

        return CompletenessReport(
            expected_hosts=expected_hosts,
            observed_hosts=observed_hosts,
            missing_hosts=missing_hosts,
            coverage_ratio=coverage,
            gaps=gaps,
            total_gap_seconds=sum(g.duration_seconds for g in gaps),
        )
