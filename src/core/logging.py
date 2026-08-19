"""Structured Logging Utilities for Lab Components."""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Format log records as structured single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include custom extra fields if provided
        if hasattr(record, "event_category"):
            log_obj["event_category"] = record.event_category
        if hasattr(record, "source_ip"):
            log_obj["source_ip"] = record.source_ip
        if hasattr(record, "user"):
            log_obj["user"] = record.user
        if hasattr(record, "extra_data"):
            log_obj["data"] = record.extra_data

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create or retrieve a structured JSON logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
