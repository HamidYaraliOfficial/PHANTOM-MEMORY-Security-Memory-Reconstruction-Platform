"""
Authentication Memory Engine.

Models Login, Logout, Token Issuance Metadata, Session Refresh, Role Change
and Authentication Method inside a single Session/Episode so the path from
Identity to Resource can be walked forward through the timeline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from phantom_memory.core.models import CanonicalSecurityEvent


@dataclass
class AuthenticationSession:
    session_id: str
    identity: str
    method: Optional[str]
    login_at: Optional[datetime]
    logout_at: Optional[datetime]
    role_changes: list[dict] = field(default_factory=list)
    token_refreshes: list[dict] = field(default_factory=list)
    resources_accessed: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    state: str = "unknown"  # active | ended | unknown


class AuthenticationMemoryEngine:
    def reconstruct(self, events: list[CanonicalSecurityEvent]) -> list[AuthenticationSession]:
        relevant = [e for e in events if e.event_category.value in ("authentication", "authorization")]
        relevant.sort(key=lambda e: e.timestamps.event_time)

        sessions: dict[str, AuthenticationSession] = {}
        for e in relevant:
            sid = e.session_id or f"{e.user_identity}-{e.timestamps.event_time.date()}"
            if sid not in sessions:
                sessions[sid] = AuthenticationSession(
                    session_id=sid,
                    identity=e.user_identity or "unknown",
                    method=e.payload_metadata.get("auth_method"),
                    login_at=None,
                    logout_at=None,
                    state="unknown",
                )
            s = sessions[sid]
            s.event_ids.append(e.event_id)
            etype = e.event_type.lower()
            if "login" in etype or "authenticate" in etype:
                s.login_at = s.login_at or e.timestamps.event_time
                s.state = "active"
                s.method = s.method or e.payload_metadata.get("auth_method")
            elif "logout" in etype or "session_end" in etype:
                s.logout_at = e.timestamps.event_time
                s.state = "ended"
            elif "refresh" in etype:
                s.token_refreshes.append({"at": e.timestamps.event_time.isoformat(), "event_id": e.event_id})
            elif "role" in etype or e.event_category.value == "authorization":
                s.role_changes.append({
                    "at": e.timestamps.event_time.isoformat(),
                    "event_id": e.event_id,
                    "detail": e.payload_metadata.get("role_change"),
                })
            if e.target_entity_id:
                s.resources_accessed.append(e.target_entity_id)

        return sorted(sessions.values(), key=lambda s: s.login_at or datetime.min)

    def identity_path(self, sessions: list[AuthenticationSession], identity: str) -> list[dict]:
        """The path this identity took, session by session, to whatever
        resources it touched — the basis for 'trace identity to resource'."""
        path = []
        for s in sessions:
            if s.identity != identity:
                continue
            path.append({
                "session_id": s.session_id,
                "login_at": s.login_at.isoformat() if s.login_at else None,
                "logout_at": s.logout_at.isoformat() if s.logout_at else None,
                "method": s.method,
                "resources": s.resources_accessed,
                "role_changes": s.role_changes,
            })
        return path
