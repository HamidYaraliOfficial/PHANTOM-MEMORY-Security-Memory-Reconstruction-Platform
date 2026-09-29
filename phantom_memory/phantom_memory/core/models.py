"""
Canonical Security Event Model.

Every piece of telemetry that enters PHANTOM MEMORY — regardless of source
(eBPF sensor, OpenTelemetry, journald/syslog, API logs, auth logs, cloud
audit metadata, Kubernetes events, application events, or a custom
connector) — is normalized into a `CanonicalSecurityEvent`. Once written,
an event is immutable: nothing in this module ever mutates a persisted
event's fields. Anything computed from an event (correlation, causality,
episode membership, detections, importance) is stored as a *derived*
artifact that references the event by ID instead of altering it.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

class EventCategory(str, Enum):
    PROCESS = "process"
    PROCESS_TREE = "process_tree"
    NETWORK_CONNECTION = "network_connection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    FILE_ACTIVITY = "file_activity"
    SERVICE_LIFECYCLE = "service_lifecycle"
    CONFIGURATION_CHANGE = "configuration_change"
    CONTAINER_LIFECYCLE = "container_lifecycle"
    API_ACTIVITY = "api_activity"
    DNS_METADATA = "dns_metadata"
    IDENTITY = "identity"
    DEVICE = "device"
    DEPLOYMENT = "deployment"
    CLOUD_RESOURCE = "cloud_resource"
    DATABASE_ACCESS = "database_access"
    SCHEDULED_JOB = "scheduled_job"
    SECURITY_CONTROL = "security_control"


class EventStage(str, Enum):
    """Pipeline stage an event record represents (kept separate so raw
    metadata is never overwritten by later enrichment)."""
    RAW = "raw"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    DERIVED = "derived"


class ProvenanceSource(str, Enum):
    EBPF_SENSOR = "ebpf_sensor"
    OPENTELEMETRY = "opentelemetry"
    JOURNALD_SYSLOG = "journald_syslog"
    API_LOG = "api_log"
    AUTH_LOG = "auth_log"
    CLOUD_AUDIT = "cloud_audit"
    KUBERNETES_EVENT = "kubernetes_event"
    APPLICATION_EVENT = "application_event"
    CUSTOM_CONNECTOR = "custom_connector"
    DERIVED_ENGINE = "derived_engine"
    SYNTHETIC = "synthetic"


class Classification(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS_LIKE = "malicious_like"
    UNKNOWN = "unknown"


class ImportanceTier(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


class EntityType(str, Enum):
    PROCESS = "process"
    USER = "user"
    SERVICE = "service"
    HOST = "host"
    CONTAINER = "container"
    NETWORK_ENDPOINT = "network_endpoint"
    FILE = "file"
    API = "api"
    DATABASE = "database"
    IDENTITY = "identity"
    CONFIGURATION = "configuration"
    DEPLOYMENT = "deployment"
    EVENT = "event"
    INCIDENT = "incident"
    EPISODE = "episode"
    SECURITY_CONTROL = "security_control"


class EdgeType(str, Enum):
    CAUSED = "caused"
    PRECEDED_BY = "preceded_by"
    FOLLOWED_BY = "followed_by"
    SPAWNED = "spawned"
    CONNECTED_TO = "connected_to"
    AUTHENTICATED_TO = "authenticated_to"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    EXECUTED = "executed"
    DEPENDS_ON = "depends_on"
    BELONGS_TO = "belongs_to"
    TRIGGERED = "triggered"
    OBSERVED_ON = "observed_on"
    RELATED_TO = "related_to"
    PART_OF_EPISODE = "part_of_episode"


class EvidenceStrength(str, Enum):
    DIRECT = "direct"
    TEMPORAL = "temporal"
    STRUCTURAL = "structural"
    SIMILARITY = "similarity"


# --------------------------------------------------------------------------- #
# Supporting value objects
# --------------------------------------------------------------------------- #

class LocationMetadata(BaseModel):
    region: Optional[str] = None
    zone: Optional[str] = None
    datacenter: Optional[str] = None
    network_segment: Optional[str] = None
    geo_country: Optional[str] = None


class ProvenanceMetadata(BaseModel):
    source: ProvenanceSource
    collector_id: Optional[str] = None
    collector_version: Optional[str] = None
    ingestion_pipeline_version: str = "1.0.0"
    raw_ref: Optional[str] = Field(
        default=None,
        description="Pointer to the raw-stage record this was derived from.",
    )


class TimestampInfo(BaseModel):
    """
    Timestamps are kept separate on purpose: host clock time, source-reported
    time, and platform receive time frequently disagree. Collapsing them into
    one field is exactly what produces corrupted timelines.
    """
    event_time: datetime = Field(description="Best-estimate time the event occurred.")
    source_time: Optional[datetime] = Field(
        default=None, description="Timestamp as reported by the originating source."
    )
    host_time: Optional[datetime] = Field(
        default=None, description="Local host clock time, before skew correction."
    )
    receive_time: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Time PHANTOM MEMORY received the event.",
    )
    monotonic_ns: Optional[int] = Field(
        default=None,
        description="Monotonic kernel/agent clock reading in nanoseconds, when available "
        "(eBPF sensors report this so ordering survives wall-clock adjustments).",
    )
    clock_corrected: bool = Field(
        default=False, description="True once the Clock Alignment Layer has adjusted event_time."
    )
    estimated_skew_ms: Optional[float] = None


class EventClassificationInfo(BaseModel):
    classification: Classification = Classification.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    tags: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Canonical Security Event
# --------------------------------------------------------------------------- #

class CanonicalSecurityEvent(BaseModel):
    """The single normalized representation every event is stored as."""

    # --- Identity & lineage -------------------------------------------------
    event_id: str
    event_type: str = Field(description="Fine-grained type, e.g. 'process.exec', 'network.connect'.")
    event_category: EventCategory
    stage: EventStage = EventStage.NORMALIZED
    schema_version: str = "1.0.0"

    parent_event_id: Optional[str] = None
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None

    # --- Timing --------------------------------------------------------------
    timestamps: TimestampInfo

    # --- Where / who / what ---------------------------------------------------
    source: ProvenanceMetadata
    actor_entity_id: Optional[str] = Field(default=None, description="Entity that performed the action.")
    target_entity_id: Optional[str] = Field(default=None, description="Entity the action was performed on.")
    entity_ids: list[str] = Field(
        default_factory=list, description="All entities referenced by this event (superset of actor/target)."
    )

    host_id: Optional[str] = None
    process_id: Optional[str] = None
    container_id: Optional[str] = None
    user_identity: Optional[str] = None
    service_identity: Optional[str] = None

    location: LocationMetadata = Field(default_factory=LocationMetadata)
    environment: Optional[str] = Field(default=None, description="e.g. production, staging, dev.")

    # --- Payload ---------------------------------------------------------------
    payload_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured, privacy-filtered metadata. Raw payloads are never stored here.",
    )

    # --- Trust / quality ---------------------------------------------------------
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    classification: EventClassificationInfo = Field(default_factory=EventClassificationInfo)
    importance_tier: ImportanceTier = ImportanceTier.LOW
    importance_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # --- Integrity -----------------------------------------------------------------
    content_hash: Optional[str] = Field(
        default=None, description="SHA-256 fingerprint over stable fields, used for dedup & integrity."
    )
    prev_hash: Optional[str] = Field(
        default=None, description="Hash of the previous event in this host's hash-chain, if enabled."
    )

    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def _ensure_actor_target_included(self) -> "CanonicalSecurityEvent":
        merged = set(self.entity_ids)
        if self.actor_entity_id:
            merged.add(self.actor_entity_id)
        if self.target_entity_id:
            merged.add(self.target_entity_id)
        self.entity_ids = sorted(merged)
        return self

    def compute_content_hash(self) -> str:
        """
        Deterministic fingerprint over fields that identify *what happened*,
        deliberately excluding volatile bookkeeping fields (ingested_at,
        receive_time, content_hash itself) so the same real-world event
        hashes identically regardless of when it was ingested.
        """
        stable = {
            "event_type": self.event_type,
            "event_category": self.event_category.value,
            "event_time": self.timestamps.event_time.isoformat(),
            "actor_entity_id": self.actor_entity_id,
            "target_entity_id": self.target_entity_id,
            "host_id": self.host_id,
            "process_id": self.process_id,
            "container_id": self.container_id,
            "user_identity": self.user_identity,
            "payload_metadata": self.payload_metadata,
            "source": self.source.source.value,
        }
        blob = json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def finalize(self) -> "CanonicalSecurityEvent":
        """Freeze integrity metadata before persistence. Call once, at write time."""
        if self.content_hash is None:
            self.content_hash = self.compute_content_hash()
        return self

    model_config = ConfigDict(use_enum_values=False)


# --------------------------------------------------------------------------- #
# Graph entities & edges
# --------------------------------------------------------------------------- #

class MemoryEntity(BaseModel):
    entity_id: str
    entity_type: EntityType
    display_name: str
    natural_key: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    attributes: dict[str, Any] = Field(default_factory=dict)
    criticality: float = Field(default=0.3, ge=0.0, le=1.0)
    merged_into: Optional[str] = Field(
        default=None, description="If set, this entity was resolved into another entity."
    )
    version: int = 1


class MemoryEdge(BaseModel):
    edge_id: str
    edge_type: EdgeType
    source_entity_id: str
    target_entity_id: str
    valid_from: datetime
    valid_to: Optional[datetime] = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_strength: EvidenceStrength = EvidenceStrength.TEMPORAL
    evidence_event_ids: list[str] = Field(default_factory=list)
    supporting_notes: Optional[str] = None
    version: int = 1
    superseded_by: Optional[str] = None


class Episode(BaseModel):
    episode_id: str
    episode_type: str
    title: str
    start_time: datetime
    end_time: Optional[datetime] = None
    entity_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: dict[str, Any] = Field(default_factory=dict)
    trigger_event_id: Optional[str] = None
    status: str = "candidate"  # candidate -> validated -> closed / rejected / merged / split / archived
    parent_episode_ids: list[str] = Field(default_factory=list)
    version: int = 1


class CausalHypothesis(BaseModel):
    hypothesis_id: str
    candidate_cause_event_id: str
    candidate_effect_event_id: str
    evidence_strength: EvidenceStrength
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_event_ids: list[str] = Field(default_factory=list)
    contradicting_event_ids: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
    rationale: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
