"""
Security Memory Importance Engine.

Produces an explainable importance score in [0, 1] for an event, factoring
in relationship count, entity criticality, position in sequence, rarity,
recency, session context, deployment context, and proximity to known
incidents. Every score comes with a `breakdown` dict so an analyst (or the
Retention Engine) can see *why* an event was scored the way it was, instead
of trusting an opaque number.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from phantom_memory.core.models import CanonicalSecurityEvent, ImportanceTier

# Base weight for each rare/common event type observed in the whole store,
# updated incrementally as events are seen (a simple frequentist rarity model).
_RARE_EVENT_TYPE_CEILING = 5  # types seen 5 times or fewer are "rare"


@dataclass
class ImportanceBreakdown:
    relationship_count_score: float = 0.0
    entity_criticality_score: float = 0.0
    rarity_score: float = 0.0
    recency_score: float = 0.0
    session_context_score: float = 0.0
    deployment_context_score: float = 0.0
    incident_proximity_score: float = 0.0
    final_score: float = 0.0
    tier: ImportanceTier = ImportanceTier.LOW

    def as_dict(self) -> dict:
        return {
            "relationship_count_score": round(self.relationship_count_score, 4),
            "entity_criticality_score": round(self.entity_criticality_score, 4),
            "rarity_score": round(self.rarity_score, 4),
            "recency_score": round(self.recency_score, 4),
            "session_context_score": round(self.session_context_score, 4),
            "deployment_context_score": round(self.deployment_context_score, 4),
            "incident_proximity_score": round(self.incident_proximity_score, 4),
            "final_score": round(self.final_score, 4),
            "tier": self.tier.value,
        }


class ImportanceEngine:
    WEIGHTS = {
        "relationship_count": 0.20,
        "entity_criticality": 0.20,
        "rarity": 0.15,
        "recency": 0.10,
        "session_context": 0.10,
        "deployment_context": 0.10,
        "incident_proximity": 0.15,
    }

    def __init__(self):
        self._event_type_counts: dict[str, int] = {}

    def observe_type(self, event_type: str) -> None:
        self._event_type_counts[event_type] = self._event_type_counts.get(event_type, 0) + 1

    def _rarity(self, event_type: str) -> float:
        count = self._event_type_counts.get(event_type, 0)
        if count <= _RARE_EVENT_TYPE_CEILING:
            return 1.0 - (count / (_RARE_EVENT_TYPE_CEILING + 1))
        # log-decaying rarity for common types
        import math

        return max(0.0, 1.0 / math.log2(count + 2))

    def _recency(self, event_time: datetime, now: Optional[datetime] = None) -> float:
        now = now or datetime.now(timezone.utc)
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        age_hours = max(0.0, (now - event_time).total_seconds() / 3600.0)
        # exponential decay, half-life ~72h
        import math

        return math.exp(-age_hours / 72.0)

    def score(
        self,
        event: CanonicalSecurityEvent,
        *,
        relationship_count: int = 0,
        entity_criticality: float = 0.3,
        in_active_session: bool = False,
        near_deployment: bool = False,
        near_known_incident: bool = False,
        now: Optional[datetime] = None,
    ) -> ImportanceBreakdown:
        self.observe_type(event.event_type)

        rel_score = min(1.0, relationship_count / 10.0)
        crit_score = max(0.0, min(1.0, entity_criticality))
        rarity_score = self._rarity(event.event_type)
        recency_score = self._recency(event.timestamps.event_time, now)
        session_score = 1.0 if in_active_session else 0.2
        deploy_score = 1.0 if near_deployment else 0.1
        incident_score = 1.0 if near_known_incident else 0.0

        w = self.WEIGHTS
        final = (
            w["relationship_count"] * rel_score
            + w["entity_criticality"] * crit_score
            + w["rarity"] * rarity_score
            + w["recency"] * recency_score
            + w["session_context"] * session_score
            + w["deployment_context"] * deploy_score
            + w["incident_proximity"] * incident_score
        )
        final = max(0.0, min(1.0, final))

        if final >= 0.8:
            tier = ImportanceTier.CRITICAL
        elif final >= 0.6:
            tier = ImportanceTier.HIGH
        elif final >= 0.35:
            tier = ImportanceTier.MEDIUM
        elif final >= 0.15:
            tier = ImportanceTier.LOW
        else:
            tier = ImportanceTier.NEGLIGIBLE

        return ImportanceBreakdown(
            relationship_count_score=rel_score,
            entity_criticality_score=crit_score,
            rarity_score=rarity_score,
            recency_score=recency_score,
            session_context_score=session_score,
            deployment_context_score=deploy_score,
            incident_proximity_score=incident_score,
            final_score=final,
            tier=tier,
        )

    def apply(self, event: CanonicalSecurityEvent, breakdown: ImportanceBreakdown) -> CanonicalSecurityEvent:
        event.importance_score = breakdown.final_score
        event.importance_tier = breakdown.tier
        return event
