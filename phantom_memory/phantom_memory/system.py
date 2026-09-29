"""
PhantomMemorySystem — the orchestration facade.

Wires the Event Store, Clock Alignment, Deduplication, Importance Engine,
Security Memory Graph, Episode Reconstruction, Temporal Memory/Snapshot/
Replay/Diff engines, Causal/Divergence/Contradiction/Confidence/
Completeness analysis, Retrieval (vector/hybrid/similarity), domain memory
engines, and the Investigation Workspace (cases/notebook/bookmarks) into a
single object that the API layer and CLI both drive.

This is intentionally the *only* place that constructs every subsystem, so
API and CLI never diverge in how the pipeline is assembled.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from phantom_memory.analysis.causal import CausalHypothesisEngine
from phantom_memory.analysis.completeness import EvidenceCompletenessEngine
from phantom_memory.analysis.confidence import MemoryConfidenceEngine
from phantom_memory.analysis.contradiction import ContradictionDetector
from phantom_memory.analysis.divergence import FirstDivergenceEngine
from phantom_memory.core.clock import ClockAlignmentLayer
from phantom_memory.core.dedup import DeduplicationEngine
from phantom_memory.core.event_store import EventStore, ImmutableEventError
from phantom_memory.core.importance import ImportanceEngine
from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.domain.authentication import AuthenticationMemoryEngine
from phantom_memory.domain.configuration import ConfigurationDiffExplorer, ConfigurationMemoryEngine
from phantom_memory.domain.network_sessions import NetworkSessionMemoryEngine
from phantom_memory.domain.process_lineage import ProcessLineageEngine
from phantom_memory.episodes.engine import EpisodeReconstructionEngine, EpisodeStore
from phantom_memory.episodes.lifecycle import EpisodeLifecycleManager
from phantom_memory.graph.entity_resolution import EntityResolutionEngine
from phantom_memory.graph.memory_graph import SecurityMemoryGraph
from phantom_memory.graph.search import GraphSearchEngine
from phantom_memory.investigation.bookmarks import EvidenceBookmarkSystem
from phantom_memory.investigation.cases import CaseManagementSystem
from phantom_memory.investigation.notebook import InvestigationNotebook
from phantom_memory.retrieval.hybrid import HybridRetrievalEngine
from phantom_memory.retrieval.similarity import HistoricalSimilarityEngine, IncidentFamilyEngine
from phantom_memory.retrieval.vector_index import VectorMemoryIndex
from phantom_memory.temporal.diff import TemporalDiffEngine
from phantom_memory.temporal.memory_engine import TemporalMemoryEngine
from phantom_memory.temporal.replay import ReplayEngine
from phantom_memory.temporal.snapshot import SnapshotEngine
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.system")


@dataclass
class IngestResult:
    accepted: bool
    event: Optional[CanonicalSecurityEvent]
    was_duplicate: bool = False
    clock_notes: list[str] = None
    reason: Optional[str] = None


class PhantomMemorySystem:
    def __init__(self, data_dir: str | Path = "data"):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)

        self.store = EventStore(data_dir / "phantom_memory.db")
        self.graph = SecurityMemoryGraph(data_dir / "phantom_graph.db")

        self.clock = ClockAlignmentLayer()
        self.dedup = DeduplicationEngine(self.store)
        self.importance = ImportanceEngine()

        self.graph_search = GraphSearchEngine(self.graph)
        self.entity_resolution = EntityResolutionEngine(self.graph)

        self.temporal_memory = TemporalMemoryEngine(self.graph)
        self.snapshots = SnapshotEngine(self.store, self.temporal_memory)
        self.replay = ReplayEngine(self.store, self.snapshots)
        self.temporal_diff = TemporalDiffEngine(self.temporal_memory)

        self.episode_engine = EpisodeReconstructionEngine(self.store, self.graph)
        self.episode_store = EpisodeStore(self.store)
        self.episode_lifecycle = EpisodeLifecycleManager(self.store)

        self.causal = CausalHypothesisEngine(self.graph)
        self.divergence = FirstDivergenceEngine()
        self.contradiction = ContradictionDetector()
        self.confidence = MemoryConfidenceEngine()
        self.completeness = EvidenceCompletenessEngine()

        self.vector_index = VectorMemoryIndex()
        self.hybrid_retrieval = HybridRetrievalEngine(self.store, self.graph_search, self.vector_index)
        self.similarity = HistoricalSimilarityEngine()
        self.incident_family = IncidentFamilyEngine(self.similarity)

        self.process_lineage = ProcessLineageEngine(self.graph)
        self.network_sessions = NetworkSessionMemoryEngine()
        self.authentication = AuthenticationMemoryEngine()
        self.configuration = ConfigurationMemoryEngine()
        self.configuration_diff = ConfigurationDiffExplorer()

        self.cases = CaseManagementSystem(self.store)
        self.notebooks = InvestigationNotebook(self.store)
        self.bookmarks = EvidenceBookmarkSystem(self.store)

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def ingest(self, event: CanonicalSecurityEvent, *, relationship_count: int = 0,
               entity_criticality: float = 0.3, in_active_session: bool = False,
               near_deployment: bool = False, near_known_incident: bool = False) -> IngestResult:
        finding = self.clock.evaluate(event)
        event = self.clock.apply_correction(event, finding)

        dedup_result = self.dedup.check(event)
        if dedup_result.is_duplicate:
            self.dedup.record_duplicate_observation(dedup_result.original_event_id, event.source.source.value)
            return IngestResult(accepted=False, event=event, was_duplicate=True,
                                 clock_notes=finding.notes, reason=dedup_result.reason)

        breakdown = self.importance.score(
            event,
            relationship_count=relationship_count,
            entity_criticality=entity_criticality,
            in_active_session=in_active_session,
            near_deployment=near_deployment,
            near_known_incident=near_known_incident,
        )
        event = self.importance.apply(event, breakdown)

        try:
            stored = self.store.write_normalized(event)
        except ImmutableEventError as exc:
            return IngestResult(accepted=False, event=event, reason=str(exc))

        self.store.add_enrichment(
            enrichment_id=f"imp_{event.event_id}",
            event_id=event.event_id,
            enrichment_type="importance_breakdown",
            payload=breakdown.as_dict(),
        )

        self._project_to_graph(stored)
        return IngestResult(accepted=True, event=stored, clock_notes=finding.notes)

    def _project_to_graph(self, event: CanonicalSecurityEvent) -> None:
        """Minimal, generic graph projection: ensures actor/target entities
        exist and links them with an edge type inferred from event_category.
        Connectors/enrichment can add richer, more specific edges on top."""
        from phantom_memory.core.models import EdgeType, EntityType, EvidenceStrength

        category_to_edge = {
            "process": EdgeType.EXECUTED,
            "network_connection": EdgeType.CONNECTED_TO,
            "authentication": EdgeType.AUTHENTICATED_TO,
            "file_activity": EdgeType.ACCESSED,
            "configuration_change": EdgeType.MODIFIED,
            "service_lifecycle": EdgeType.TRIGGERED,
        }
        if not event.actor_entity_id or not event.target_entity_id:
            return

        self.graph.upsert_entity(
            EntityType.PROCESS if event.process_id else EntityType.USER,
            event.actor_entity_id, natural_key=event.actor_entity_id, at_time=event.timestamps.event_time,
        )
        self.graph.upsert_entity(
            EntityType.NETWORK_ENDPOINT if event.event_category.value == "network_connection" else EntityType.FILE,
            event.target_entity_id, natural_key=event.target_entity_id, at_time=event.timestamps.event_time,
        )
        edge_type = category_to_edge.get(event.event_category.value, EdgeType.RELATED_TO)
        self.graph.add_edge(
            edge_type,
            event.actor_entity_id,
            event.target_entity_id,
            valid_from=event.timestamps.event_time,
            confidence=event.confidence,
            evidence_strength=EvidenceStrength.DIRECT,
            evidence_event_ids=[event.event_id],
        )

    # ------------------------------------------------------------------ #
    # Reconstruction
    # ------------------------------------------------------------------ #
    def reconstruct_episodes(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ):
        events = self.store.query(start_time=start_time, end_time=end_time, limit=100_000)
        episodes = self.episode_engine.reconstruct(events)
        for ep in episodes:
            summary_text = f"{ep.title} entities={ep.entity_ids} events={len(ep.event_ids)}"
            self.vector_index.upsert(ep.episode_id, summary_text, {"type": "episode", "episode_type": ep.episode_type})
        return episodes
