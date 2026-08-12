"""Logging configuration that redacts credential-shaped output."""

from __future__ import annotations

import logging as stdlib_logging

from safeinstall.redaction import redact_text


class RedactingFormatter(stdlib_logging.Formatter):
    """Apply redaction after message arguments and exceptions are formatted."""

    def format(self, record: stdlib_logging.LogRecord) -> str:
        return redact_text(super().format(record))


def configure_logging(*, verbose: bool = False) -> None:
    """Configure SafeInstall's package logger without exposing secret-shaped values."""

    handler = stdlib_logging.StreamHandler()
    handler.setFormatter(RedactingFormatter("%(levelname)s: %(message)s"))
    logger = stdlib_logging.getLogger("safeinstall")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(stdlib_logging.DEBUG if verbose else stdlib_logging.WARNING)
