import logging
import sys
from typing import Any, Dict

import structlog


def _configure_logging() -> None:
    timestamper = structlog.processors.TimeStamper(fmt="iso")

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers = [handler]


_configure_logging()

logger: structlog.stdlib.BoundLogger = structlog.get_logger("secure_app")


def log_security_event(event: str, **kwargs: Dict[str, Any]) -> None:
    """
    Structured security event logging.
    Never log sensitive data such as passwords, tokens, or full PII values.
    """
    safe_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    logger.info("security_event", event=event, **safe_kwargs)


