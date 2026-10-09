"""Structured JSON logging with request context. Never log tokens, signed URLs or file content."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime

from app.core.context import get_log_context

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}
_SENSITIVE_KEY = re.compile(
    r"(token|secret|password|authorization|api[_-]?key|signature|cookie)", re.I
)
_URL_TOKEN = re.compile(r"(token=)[^&\s]+", re.I)


def _redact(key: str, value: object) -> object:
    if _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, str):
        return _URL_TOKEN.sub(r"\1[REDACTED]", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": _URL_TOKEN.sub(r"\1[REDACTED]", record.getMessage()),
            **{k: v for k, v in get_log_context().items() if v},
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _redact(key, value)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # httpx logs full URLs at INFO (may contain signed tokens) - keep it quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").handlers[:] = []
    logging.getLogger("uvicorn.access").propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
