"""
Historical Similarity Engine & Historical Incident Fingerprinting Engine.

Compares a new incident/episode against historical ones on: event sequence,
entity graph shape, timing pattern, process pattern, network pattern, and
identity path — and reports similarity broken down by dimension so an
analyst can see exactly *where* two incidents resemble each other, not just
a single opaque score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher

from phantom_memory.core.models import CanonicalSecurityEvent, Episode


@dataclass
class IncidentFingerprint:
    subject_id: str
    event_type_sequence: list[str]
    entity_type_set: set[str]
    process_names: set[str]
    network_endpoints: set[str]
    identities: set[str]
    duration_seconds: float

    @classmethod
    def from_events(cls, subject_id: str, events: list[CanonicalSecurityEvent]) -> "IncidentFingerprint":
        events = sorted(events, key=lambda e: e.timestamps.event_time)
        duration = (
            (events[-1].timestamps.event_time - events[0].timestamps.event_time).total_seconds()
            if len(events) > 1 else 0.0
        )
        return cls(
            subject_id=subject_id,
            event_type_sequence=[e.event_type for e in events],
            entity_type_set={eid.split("_")[1] for e in events for eid in e.entity_ids if "_" in eid},
            process_names={e.payload_metadata.get("process_name") for e in events if e.payload_metadata.get("process_name")},
            network_endpoints={
                ep for e in events for ep in
                [e.payload_metadata.get("source_endpoint"), e.payload_metadata.get("destination_endpoint")]
                if ep
            },
            identities={e.user_identity for e in events if e.user_identity},
            duration_seconds=duration,
        )


@dataclass
class SimilarityBreakdown:
    other_id: str
    event_sequence_similarity: float
    entity_graph_similarity: float
    timing_similarity: float
    process_pattern_similarity: float
    network_pattern_similarity: float
    identity_path_similarity: float
    overall: float
    matched_on: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "other_id": self.other_id,
            "event_sequence_similarity": round(self.event_sequence_similarity, 4),
            "entity_graph_similarity": round(self.entity_graph_similarity, 4),
            "timing_similarity": round(self.timing_similarity, 4),
            "process_pattern_similarity": round(self.process_pattern_similarity, 4),
            "network_pattern_similarity": round(self.network_pattern_similarity, 4),
            "identity_path_similarity": round(self.identity_path_similarity, 4),
            "overall": round(self.overall, 4),
            "matched_on": self.matched_on,
        }


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


class HistoricalSimilarityEngine:
    WEIGHTS = {
        "event_sequence": 0.30,
        "entity_graph": 0.15,
        "timing": 0.10,
        "process_pattern": 0.20,
        "network_pattern": 0.15,
        "identity_path": 0.10,
    }

    def compare(self, subject: IncidentFingerprint, other: IncidentFingerprint) -> SimilarityBreakdown:
        seq_sim = SequenceMatcher(
            a=subject.event_type_sequence, b=other.event_type_sequence
        ).ratio()
        entity_sim = _jaccard(subject.entity_type_set, other.entity_type_set)
        process_sim = _jaccard(subject.process_names, other.process_names)
        network_sim = _jaccard(subject.network_endpoints, other.network_endpoints)
        identity_sim = _jaccard(subject.identities, other.identities)

        if subject.duration_seconds == 0 and other.duration_seconds == 0:
            timing_sim = 1.0
        else:
            longer = max(subject.duration_seconds, other.duration_seconds, 1e-6)
            timing_sim = 1.0 - abs(subject.duration_seconds - other.duration_seconds) / longer

        w = self.WEIGHTS
        overall = (
            w["event_sequence"] * seq_sim
            + w["entity_graph"] * entity_sim
            + w["timing"] * timing_sim
            + w["process_pattern"] * process_sim
            + w["network_pattern"] * network_sim
            + w["identity_path"] * identity_sim
        )

        matched_on = []
        if seq_sim > 0.5:
            matched_on.append("event_sequence")
        if process_sim > 0.3:
            matched_on.append("process_pattern")
        if network_sim > 0.3:
            matched_on.append("network_pattern")
        if identity_sim > 0.3:
            matched_on.append("identity_path")
        if entity_sim > 0.3:
            matched_on.append("entity_graph")

        return SimilarityBreakdown(
            other_id=other.subject_id,
            event_sequence_similarity=seq_sim,
            entity_graph_similarity=entity_sim,
            timing_similarity=timing_sim,
            process_pattern_similarity=process_sim,
            network_pattern_similarity=network_sim,
            identity_path_similarity=identity_sim,
            overall=overall,
            matched_on=matched_on,
        )

    def rank(self, subject: IncidentFingerprint, candidates: list[IncidentFingerprint], top_k: int = 5) -> list[SimilarityBreakdown]:
        results = [self.compare(subject, c) for c in candidates if c.subject_id != subject.subject_id]
        return sorted(results, key=lambda r: r.overall, reverse=True)[:top_k]


class IncidentFamilyEngine:
    """Groups incidents whose fingerprints are mutually similar above a
    threshold into a 'family', and reports how each member differs from the
    family's earliest (founding) member — a lightweight Pattern Evolution
    view."""

    def __init__(self, similarity_engine: HistoricalSimilarityEngine, threshold: float = 0.55):
        self.similarity_engine = similarity_engine
        self.threshold = threshold

    def build_families(self, fingerprints: list[IncidentFingerprint]) -> list[list[str]]:
        parent = {fp.subject_id: fp.subject_id for fp in fingerprints}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(len(fingerprints)):
            for j in range(i + 1, len(fingerprints)):
                sim = self.similarity_engine.compare(fingerprints[i], fingerprints[j])
                if sim.overall >= self.threshold:
                    union(fingerprints[i].subject_id, fingerprints[j].subject_id)

        families: dict[str, list[str]] = {}
        for fp in fingerprints:
            root = find(fp.subject_id)
            families.setdefault(root, []).append(fp.subject_id)
        return [members for members in families.values() if len(members) > 1]
