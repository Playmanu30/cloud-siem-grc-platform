"""
Logging and Utility Functions
"""

import logging
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import structlog


def setup_logging(log_level: str = "INFO", json_output: bool = True) -> None:
    """Configure structured logging (JSON in production, readable console in dev)"""
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(format="%(message)s", level=level, force=True)
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
            if json_output
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance"""
    return structlog.get_logger(name)


class SecurityEvent:
    """Represents a security event for logging and alerting"""

    def __init__(
        self,
        event_type: str,
        severity: str,
        source: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.event_type = event_type
        self.severity = severity  # critical, high, medium, low, info
        self.source = source
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "timestamp": self.timestamp,
            "details": self.details,
        }

    def to_json(self) -> str:
        """Convert event to JSON"""
        return json.dumps(self.to_dict())


def severity_to_level(severity: str) -> int:
    """Convert severity string to logging level"""
    mapping = {
        "critical": logging.CRITICAL,
        "high": logging.ERROR,
        "medium": logging.WARNING,
        "low": logging.INFO,
        "info": logging.INFO,
    }
    return mapping.get(severity.lower(), logging.INFO)
