"""
Incident Memory Lifecycle.

Episodes are born as `candidate`, strengthened by correlation/evidence, and
then an analyst can Validate, Reject, Merge, Split, Close, or Archive them.
Merge and Split always preserve provenance: a merged episode records both
parents in `parent_episode_ids`, and a split's children each point back at
the episode they were split from.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from phantom_memory.core.event_store import EventStore
from phantom_memory.core.models import Episode
from phantom_memory.episodes.engine import ALGO_VERSION, EpisodeStore
from phantom_memory.utils.ids import new_episode_id
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.episode_lifecycle")

_VALID_TRANSITIONS = {
    "candidate": {"validated", "rejected", "merged", "split", "archived"},
    "validated": {"closed", "merged", "split", "archived"},
    "closed": {"archived", "validated"},  # 'validated' here represents a reopen
    "rejected": {"archived"},
    "merged": {"archived"},
    "split": {"archived"},
}


class InvalidTransitionError(Exception):
    pass


class EpisodeLifecycleManager:
    def __init__(self, store: EventStore):
        self.store = store
        self.episodes = EpisodeStore(store)

    def _persist(self, episode: Episode) -> None:
        self.store.write_derived(
            artifact_id=episode.episode_id,
            artifact_type="episode",
            event_ids=episode.event_ids,
            payload=episode.model_dump(mode="json"),
            algorithm_version=ALGO_VERSION,
        )

    def _transition(self, episode: Episode, new_status: str) -> Episode:
        allowed = _VALID_TRANSITIONS.get(episode.status, set())
        if new_status not in allowed:
            raise InvalidTransitionError(f"cannot move episode from {episode.status} to {new_status}")
        episode.status = new_status
        episode.version += 1
        self._persist(episode)
        logger.info("episode_transition", extra={"extra_fields": {
            "episode_id": episode.episode_id, "new_status": new_status
        }})
        return episode

    def validate(self, episode_id: str) -> Episode:
        ep = self._require(episode_id)
        return self._transition(ep, "validated")

    def reject(self, episode_id: str, reason: str) -> Episode:
        ep = self._require(episode_id)
        ep.context["rejection_reason"] = reason
        return self._transition(ep, "rejected")

    def close(self, episode_id: str, resolution_notes: str = "") -> Episode:
        ep = self._require(episode_id)
        if resolution_notes:
            ep.context["resolution_notes"] = resolution_notes
        return self._transition(ep, "closed")

    def archive(self, episode_id: str) -> Episode:
        ep = self._require(episode_id)
        return self._transition(ep, "archived")

    def merge(self, episode_ids: list[str], title: Optional[str] = None) -> Episode:
        parents = [self._require(eid) for eid in episode_ids]
        event_ids = sorted({eid for p in parents for eid in p.event_ids})
        entity_ids = sorted({eid for p in parents for eid in p.entity_ids})
        start = min(p.start_time for p in parents)
        end = max((p.end_time or p.start_time) for p in parents)
        merged = Episode(
            episode_id=new_episode_id(),
            episode_type=parents[0].episode_type,
            title=title or f"Merged episode ({len(parents)} sources)",
            start_time=start,
            end_time=end,
            entity_ids=entity_ids,
            event_ids=event_ids,
            confidence=sum(p.confidence for p in parents) / len(parents),
            context={"merged_from": [p.episode_id for p in parents]},
            status="candidate",
            parent_episode_ids=[p.episode_id for p in parents],
        )
        self._persist(merged)
        for p in parents:
            self._transition(p, "merged")
        return merged

    def split(self, episode_id: str, event_id_groups: list[list[str]], titles: Optional[list[str]] = None) -> list[Episode]:
        parent = self._require(episode_id)
        titles = titles or [f"{parent.title} (split {i+1})" for i in range(len(event_id_groups))]
        children: list[Episode] = []
        for group, title in zip(event_id_groups, titles):
            entity_ids = set()
            child = Episode(
                episode_id=new_episode_id(),
                episode_type=parent.episode_type,
                title=title,
                start_time=parent.start_time,
                end_time=parent.end_time,
                entity_ids=parent.entity_ids,
                event_ids=group,
                confidence=parent.confidence,
                context={"split_from": parent.episode_id},
                status="candidate",
                parent_episode_ids=[parent.episode_id],
            )
            self._persist(child)
            children.append(child)
        self._transition(parent, "split")
        return children

    def _require(self, episode_id: str) -> Episode:
        ep = self.episodes.get(episode_id)
        if ep is None:
            raise KeyError(f"episode {episode_id} not found")
        return ep
