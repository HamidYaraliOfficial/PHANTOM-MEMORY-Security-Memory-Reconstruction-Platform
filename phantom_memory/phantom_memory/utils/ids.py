"""
ID generation utilities for PHANTOM MEMORY.

All identifiers used across the platform (event, entity, episode, incident,
case, snapshot, branch) are generated here so that ID shape stays consistent
and traceable back to its subsystem.
"""
from __future__ import annotations

import secrets
import time
import uuid


def _rand_suffix(n: int = 8) -> str:
    return secrets.token_hex(n // 2)


def new_event_id() -> str:
    return f"evt_{uuid.uuid4().hex}"


def new_entity_id(entity_type: str, natural_key: str | None = None) -> str:
    """
    Entity IDs are deterministic when a natural key is supplied, so the same
    real-world entity (e.g. host+pid+start_time, or username) resolves to the
    same node instead of duplicating it. This is what Entity Resolution
    relies on as a first, cheap pass before graph-based merging.
    """
    entity_type = entity_type.lower().strip()
    if natural_key:
        digest = uuid.uuid5(uuid.NAMESPACE_URL, f"{entity_type}:{natural_key}")
        return f"ent_{entity_type}_{digest.hex[:24]}"
    return f"ent_{entity_type}_{uuid.uuid4().hex[:24]}"


def new_episode_id() -> str:
    return f"epi_{uuid.uuid4().hex}"


def new_incident_id() -> str:
    return f"inc_{uuid.uuid4().hex}"


def new_case_id() -> str:
    return f"case_{uuid.uuid4().hex[:12]}"


def new_snapshot_id() -> str:
    return f"snap_{int(time.time())}_{_rand_suffix()}"


def new_branch_id() -> str:
    return f"branch_{uuid.uuid4().hex[:12]}"


def new_hypothesis_id() -> str:
    return f"hyp_{uuid.uuid4().hex[:16]}"


def new_bookmark_id() -> str:
    return f"bkm_{uuid.uuid4().hex[:12]}"


def new_note_id() -> str:
    return f"note_{uuid.uuid4().hex[:12]}"


def new_query_id() -> str:
    return f"qry_{uuid.uuid4().hex[:12]}"


def new_correlation_id() -> str:
    return f"corr_{uuid.uuid4().hex[:16]}"
