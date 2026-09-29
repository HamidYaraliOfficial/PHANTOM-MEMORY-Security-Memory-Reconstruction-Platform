"""
Network Session Memory Engine.

Turns raw connect/accept/close events into reconstructable Network Session
episodes, keeping precise created/ongoing/terminated timing so a session can
be re-examined long after the connection itself closed.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class NetworkSession:
    session_key: str
    source_endpoint: str
    destination_endpoint: str
    protocol: Optional[str]
    created_at: datetime
    last_activity_at: datetime
    terminated_at: Optional[datetime]
    state: str  # 'open' | 'closed' | 'unknown'
    event_ids: list[str]
    bytes_hint: Optional[int] = None


class NetworkSessionMemoryEngine:
    def reconstruct(self, events: list[CanonicalSecurityEvent]) -> list[NetworkSession]:
        events = [e for e in events if e.event_category.value == "network_connection"]
        events.sort(key=lambda e: e.timestamps.event_time)

        sessions: dict[str, NetworkSession] = {}
        for e in events:
            src = e.payload_metadata.get("source_endpoint")
            dst = e.payload_metadata.get("destination_endpoint")
            proto = e.payload_metadata.get("protocol")
            if not src or not dst:
                continue
            key = e.correlation_id or f"{src}|{dst}|{proto}"
            phase = e.payload_metadata.get("tcp_state") or e.event_type

            if key not in sessions:
                sessions[key] = NetworkSession(
                    session_key=key,
                    source_endpoint=src,
                    destination_endpoint=dst,
                    protocol=proto,
                    created_at=e.timestamps.event_time,
                    last_activity_at=e.timestamps.event_time,
                    terminated_at=None,
                    state="open",
                    event_ids=[],
                )
            session = sessions[key]
            session.last_activity_at = e.timestamps.event_time
            session.event_ids.append(e.event_id)
            if "close" in str(phase).lower() or "fin" in str(phase).lower() or "rst" in str(phase).lower():
                session.terminated_at = e.timestamps.event_time
                session.state = "closed"
            if "bytes" in e.payload_metadata:
                session.bytes_hint = (session.bytes_hint or 0) + int(e.payload_metadata.get("bytes", 0))

        return sorted(sessions.values(), key=lambda s: s.created_at)
