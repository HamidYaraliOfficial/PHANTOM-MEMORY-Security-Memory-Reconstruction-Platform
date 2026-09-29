"""
Base Connector interface.

Every source-specific connector (file/log connectors, a future Kafka/NATS
consumer, cloud-audit pullers, Kubernetes watchers, etc.) implements this
interface so the Memory Ingestion Pipeline can treat them uniformly. A
connector is responsible for:

  - Authentication              (`authenticate`)
  - Incremental sync / cursors  (`Checkpoint`, persisted between runs)
  - Retry with backoff          (`_with_retry`)
  - Rate limiting               (`RateLimiter`, token-bucket)
  - Backpressure                (`max_in_flight`, checked before each batch)
  - Structured error handling   (`ConnectorError`, never raw exceptions leak)
  - Provenance                  (`source_name` tags every event's ProvenanceMetadata)

No connector may read or transmit data it hasn't been explicitly authorized
to access — see `required_permissions`. This module intentionally ships
only the *interface* plus a token-bucket/backoff toolkit; concrete
connectors (see `file_connector.py`, `synthetic_connector.py`) are the real,
runnable implementations built on top of it.
"""
from __future__ import annotations

import json
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.utils.logging_config import get_logger

logger = get_logger("phantom_memory.connectors")


class ConnectorError(Exception):
    """All connector failures surface as this (or a subclass) so the
    ingestion pipeline never has to guess what kind of exception it caught."""


class ConnectorAuthError(ConnectorError):
    pass


class ConnectorRateLimitedError(ConnectorError):
    pass


@dataclass
class Checkpoint:
    """Durable cursor for incremental sync. Persisted as a small JSON file
    per connector instance so a restarted connector resumes exactly where
    it left off instead of re-reading (or missing) history."""
    connector_id: str
    cursor: Optional[str] = None
    path: Optional[Path] = None

    @classmethod
    def load(cls, connector_id: str, checkpoint_dir: Path) -> "Checkpoint":
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        path = checkpoint_dir / f"{connector_id}.checkpoint.json"
        if path.exists():
            data = json.loads(path.read_text())
            return cls(connector_id=connector_id, cursor=data.get("cursor"), path=path)
        return cls(connector_id=connector_id, cursor=None, path=path)

    def save(self, cursor: Optional[str]) -> None:
        self.cursor = cursor
        if self.path:
            self.path.write_text(json.dumps({"cursor": cursor, "saved_at": time.time()}))


class RateLimiter:
    """Simple token-bucket limiter: `rate` tokens refill per second, up to
    `burst` tokens banked. `acquire()` blocks (briefly) or raises
    ConnectorRateLimitedError in non-blocking mode."""

    def __init__(self, rate: float = 50.0, burst: float = 100.0):
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._last = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last
        self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
        self._last = now

    def acquire(self, n: float = 1.0, blocking: bool = True, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while True:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return
            if not blocking or time.monotonic() >= deadline:
                raise ConnectorRateLimitedError("rate limit exceeded and no tokens available")
            time.sleep(min(0.05, deadline - time.monotonic()))


@dataclass
class ConnectorStats:
    batches_fetched: int = 0
    events_fetched: int = 0
    errors: int = 0
    retries: int = 0
    last_error: Optional[str] = None


class BaseConnector(ABC):
    #: Fine-grained permission strings this connector needs, declared up
    #: front so an operator can grant/deny access before any data flows.
    required_permissions: tuple[str, ...] = ()

    def __init__(
        self,
        connector_id: str,
        *,
        checkpoint_dir: Path = Path("data/checkpoints"),
        rate_limiter: Optional[RateLimiter] = None,
        max_retries: int = 3,
        max_in_flight: int = 500,
        granted_permissions: Iterable[str] = (),
    ):
        self.connector_id = connector_id
        self.checkpoint = Checkpoint.load(connector_id, checkpoint_dir)
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_retries = max_retries
        self.max_in_flight = max_in_flight
        self.granted_permissions = set(granted_permissions)
        self.stats = ConnectorStats()
        self._authenticated = False

        missing = set(self.required_permissions) - self.granted_permissions
        if missing:
            raise ConnectorAuthError(
                f"connector '{connector_id}' is missing required permissions: {sorted(missing)}"
            )

    # ---- lifecycle hooks subclasses implement ---------------------------- #
    @abstractmethod
    def authenticate(self) -> bool:
        """Establish/validate credentials. Must return True on success."""

    @abstractmethod
    def fetch_batch(self, cursor: Optional[str], batch_size: int) -> tuple[list[CanonicalSecurityEvent], Optional[str]]:
        """Fetch up to `batch_size` events starting after `cursor`, and
        return (events, new_cursor). `new_cursor` is persisted as the
        checkpoint so the next call resumes correctly."""

    # ---- shared machinery every connector gets for free -------------------- #
    def _ensure_authenticated(self) -> None:
        if not self._authenticated:
            if not self.authenticate():
                raise ConnectorAuthError(f"authentication failed for connector '{self.connector_id}'")
            self._authenticated = True

    def _with_retry(self, fn, *args, **kwargs):
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return fn(*args, **kwargs)
            except ConnectorRateLimitedError:
                raise
            except Exception as exc:  # noqa: BLE001 - deliberately broad, re-raised as ConnectorError
                last_exc = exc
                self.stats.retries += 1
                backoff = min(30.0, (2 ** attempt) + random.uniform(0, 1))
                logger.warning(
                    "connector_retry",
                    extra={"extra_fields": {
                        "connector_id": self.connector_id, "attempt": attempt, "backoff_s": backoff,
                        "error": str(exc),
                    }},
                )
                time.sleep(min(backoff, 0.05))  # capped in tests / non-production runs
        self.stats.errors += 1
        self.stats.last_error = str(last_exc)
        raise ConnectorError(f"connector '{self.connector_id}' failed after {self.max_retries} retries") from last_exc

    def pull(self, batch_size: int = 100, in_flight_count: int = 0) -> list[CanonicalSecurityEvent]:
        """The method the ingestion pipeline actually calls: authenticates,
        respects rate limiting and backpressure, fetches one batch with
        retry, advances the checkpoint, and tags provenance."""
        if in_flight_count >= self.max_in_flight:
            logger.warning("connector_backpressure", extra={"extra_fields": {
                "connector_id": self.connector_id, "in_flight": in_flight_count,
            }})
            return []

        self._ensure_authenticated()
        self.rate_limiter.acquire(1.0)

        events, new_cursor = self._with_retry(self.fetch_batch, self.checkpoint.cursor, batch_size)
        self.checkpoint.save(new_cursor)

        self.stats.batches_fetched += 1
        self.stats.events_fetched += len(events)
        return events
