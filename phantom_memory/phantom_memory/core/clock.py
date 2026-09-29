"""
Clock Alignment Layer.

Detects clock skew, out-of-order events, duplicate events, late arrivals,
and drift so that downstream timelines are not built on top of lies the
clocks told. This module never silently "fixes" event_time without leaving
a record: every correction is reflected in `TimestampInfo.clock_corrected`
and `estimated_skew_ms`, and the qualitative finding is returned to the
caller (typically the ingestion pipeline / Telemetry Integrity Engine) so it
can factor into confidence and Data Quality signals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class ClockFinding:
    host_id: Optional[str]
    event_id: str
    is_out_of_order: bool = False
    is_late_arrival: bool = False
    is_possible_duplicate_time: bool = False
    estimated_skew_ms: Optional[float] = None
    notes: list[str] = field(default_factory=list)


class ClockAlignmentLayer:
    """
    Keeps a small rolling window of (host_id -> last event_time / receive_time)
    to estimate skew and flag anomalies without needing a full external NTP
    reference. This is intentionally conservative: it flags, it does not
    silently discard data.
    """

    def __init__(self, late_arrival_threshold: timedelta = timedelta(minutes=5),
                 skew_alert_threshold_ms: float = 2000.0):
        self._last_event_time: dict[str, datetime] = {}
        self._last_receive_time: dict[str, datetime] = {}
        self.late_arrival_threshold = late_arrival_threshold
        self.skew_alert_threshold_ms = skew_alert_threshold_ms

    def evaluate(self, event: CanonicalSecurityEvent) -> ClockFinding:
        host = event.host_id or "unknown-host"
        ts = event.timestamps
        finding = ClockFinding(host_id=event.host_id, event_id=event.event_id)

        # Skew: difference between host-reported time and platform receive time.
        if ts.host_time is not None:
            skew_ms = (ts.receive_time - ts.host_time).total_seconds() * 1000.0
            finding.estimated_skew_ms = skew_ms
            if abs(skew_ms) >= self.skew_alert_threshold_ms:
                finding.notes.append(
                    f"host clock skew of {skew_ms:.0f}ms detected against platform receive time"
                )

        # Out-of-order: event_time earlier than the last event_time seen for this host.
        last_et = self._last_event_time.get(host)
        if last_et is not None and ts.event_time < last_et:
            finding.is_out_of_order = True
            finding.notes.append(
                f"event_time {ts.event_time.isoformat()} precedes last seen "
                f"{last_et.isoformat()} for host {host}"
            )

        # Late arrival: large gap between when it happened and when it arrived.
        arrival_gap = ts.receive_time - ts.event_time
        if arrival_gap > self.late_arrival_threshold:
            finding.is_late_arrival = True
            finding.notes.append(f"arrived {arrival_gap} after event_time")

        # Possible duplicate-time burst: many events at exactly the same instant
        # from the same host can indicate replayed/batched telemetry.
        last_rt = self._last_receive_time.get(host)
        if last_rt is not None and ts.event_time == last_et:
            finding.is_possible_duplicate_time = True
            finding.notes.append("identical event_time to immediately preceding event on this host")

        self._last_event_time[host] = max(last_et, ts.event_time) if last_et else ts.event_time
        self._last_receive_time[host] = ts.receive_time
        return finding

    def apply_correction(self, event: CanonicalSecurityEvent, finding: ClockFinding) -> CanonicalSecurityEvent:
        """Record the finding on the event's timestamp info without inventing
        a 'corrected' time we can't justify — we only mark that skew was
        estimated, downstream consumers decide whether to compensate."""
        if finding.estimated_skew_ms is not None:
            event.timestamps.estimated_skew_ms = finding.estimated_skew_ms
            event.timestamps.clock_corrected = True
        return event
