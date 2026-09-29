"""
File Connector.

A real, runnable connector that tails a newline-delimited JSON (NDJSON) file
of pre-canonicalized or raw events — the common shape for application logs,
exported audit logs, or any batch export dropped on disk. Incremental sync
is implemented with a byte-offset cursor, so re-running the connector after
a restart resumes exactly where it left off without re-ingesting the whole
file or missing lines appended since the last run.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from phantom_memory.core.models import CanonicalSecurityEvent
from phantom_memory.ingestion.connectors.base import BaseConnector, ConnectorError


class FileConnector(BaseConnector):
    required_permissions = ("read_local_file",)

    def __init__(
        self,
        connector_id: str,
        file_path: Path,
        *,
        record_parser: Optional[Callable[[dict], CanonicalSecurityEvent]] = None,
        **kwargs,
    ):
        self.file_path = Path(file_path)
        self.record_parser = record_parser or self._default_parser
        super().__init__(connector_id, **kwargs)

    def authenticate(self) -> bool:
        # "Authentication" for a local file connector is simply verifying
        # the file is readable under the granted permission.
        return self.file_path.exists() and self.file_path.is_file()

    @staticmethod
    def _default_parser(raw: dict) -> CanonicalSecurityEvent:
        return CanonicalSecurityEvent.model_validate(raw)

    def fetch_batch(
        self, cursor: Optional[str], batch_size: int
    ) -> tuple[list[CanonicalSecurityEvent], Optional[str]]:
        import json

        start_offset = int(cursor) if cursor else 0
        events: list[CanonicalSecurityEvent] = []
        try:
            with self.file_path.open("r", encoding="utf-8") as fh:
                fh.seek(start_offset)
                offset = start_offset
                for _ in range(batch_size):
                    line = fh.readline()
                    if not line:
                        break
                    offset = fh.tell()
                    line = line.strip()
                    if not line:
                        continue
                    raw = json.loads(line)
                    events.append(self.record_parser(raw))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConnectorError(f"failed reading '{self.file_path}': {exc}") from exc

        return events, str(offset)
