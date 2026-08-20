"""Structured Logging Utilities for Lab Components.

Provides JSON-formatted log streams, contextual metadata enrichment (correlation IDs,
source IP, user context), and automated secret scrubbing to prevent credential leakage.
"""

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Regular expressions to sanitize common sensitive patterns from log messages
SENSITIVE_PATTERNS = [
    (re.compile(r'(password|passwd|pwd|secret|api_key|token|access_token|private_key)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'(bearer\s+)([a-zA-Z0-9_\-\.]{15,})', re.IGNORECASE), r'\1***REDACTED***'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----'), '***REDACTED_PRIVATE_KEY***'),
]


def scrub_sensitive_data(text: str) -> str:
    """Scrub passwords, tokens, API keys, and private keys from log messages."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class JSONFormatter(logging.Formatter):
    """Format log records as structured single-line JSON objects with sanitization."""

    def format(self, record: logging.LogRecord) -> str:
        msg = record.getMessage()
        sanitized_msg = scrub_sensitive_data(msg)

        log_obj: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitized_msg,
        }

        # Include custom contextual fields if provided
        if hasattr(record, "correlation_id"):
            log_obj["correlation_id"] = record.correlation_id
        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id
        if hasattr(record, "event_category"):
            log_obj["event_category"] = record.event_category
        if hasattr(record, "source_ip"):
            log_obj["source_ip"] = record.source_ip
        if hasattr(record, "user"):
            log_obj["user"] = record.user
        if hasattr(record, "extra_data"):
            log_obj["data"] = record.extra_data

        if record.exc_info:
            log_obj["exception"] = scrub_sensitive_data(self.formatException(record.exc_info))

        return json.dumps(log_obj)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create or retrieve a structured JSON logger with safety sanitization."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
