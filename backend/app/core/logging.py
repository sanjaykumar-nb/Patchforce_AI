"""
PatchForge AI - Structured Logging & Correlation Engine
======================================================
Provides structured JSON logging with context-propagated Correlation IDs
(Request-ID, Pipeline-ID, Job-ID) across all asynchronous operations.
"""

import sys
import os
import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Context variables for distributed request and pipeline correlation
request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id_ctx", default=None)
pipeline_id_ctx: ContextVar[Optional[str]] = ContextVar("pipeline_id_ctx", default=None)


class JSONFormatter(logging.Formatter):
    """
    Formats log records into structured JSON objects suitable for SIEM,
    CloudWatch, Datadog, Elasticsearch, or console analysis.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "process_id": os.getpid(),
        }

        # Attach correlation IDs if present in async context
        req_id = request_id_ctx.get()
        if req_id:
            log_entry["request_id"] = req_id

        pipe_id = pipeline_id_ctx.get()
        if pipe_id:
            log_entry["pipeline_id"] = pipe_id

        # Attach custom extra fields if passed
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_entry["extra"] = record.extra_data

        # Attach exception traceback if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(log_level: str = "INFO", json_format: bool = False) -> None:
    """Configures root logger and standard streams."""
    root_logger = logging.getLogger()
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        # Standard human-readable console formatter for development
        standard_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        console_handler.setFormatter(logging.Formatter(standard_format, datefmt="%Y-%m-%d %H:%M:%S"))

    root_logger.addHandler(console_handler)

    # Silence excessively verbose third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Returns a named logger instance."""
    return logging.getLogger(name)
