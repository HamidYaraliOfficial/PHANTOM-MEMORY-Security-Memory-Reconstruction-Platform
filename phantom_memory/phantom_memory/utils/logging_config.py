"""
Structured logging for PHANTOM MEMORY.

Every log line is emitted as JSON with a fixed set of correlation fields
(trace_id, event_id, episode_id, incident_id, host_id, agent_id, case_id,
correlation_id) so that logs from every subsystem can be joined together
during an investigation. No sensitive payload is ever logged directly —
callers pass structured `extra=` fields, never raw event payloads.
"""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

_CORRELATION_FIELDS = (
    "trace_id",
    "event_id",
    "episode_id",
    "incident_id",
    "host_id",
    "agent_id",
    "case_id",
    "correlation_id",
)

_ctx: ContextVar[dict] = ContextVar("phantom_log_ctx", default={})

_REDACT_KEYS = {"password", "secret", "token", "api_key", "authorization", "credential"}


def bind_context(**kwargs: Any) -> None:
    """Bind correlation fields to the current async/thread context."""
    current = dict(_ctx.get())
    current.update({k: v for k, v in kwargs.items() if k in _CORRELATION_FIELDS})
    _ctx.set(current)


def clear_context() -> None:
    _ctx.set({})


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: ("***REDACTED***" if k.lower() in _REDACT_KEYS else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(_ctx.get())
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload["fields"] = _redact(extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def log_event(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"extra_fields": fields})
