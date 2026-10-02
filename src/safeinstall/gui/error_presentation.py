"""Map internal exceptions to calm, redacted ordinary-user messages."""

from __future__ import annotations

from dataclasses import dataclass

from safeinstall.exceptions import (
    AIUnavailableError,
    InputError,
    NoScannableFilesError,
    RepositoryLoadError,
    UnsafeArchiveError,
)
from safeinstall.gui.i18n import Catalog
from safeinstall.redaction import redact_text


@dataclass(frozen=True, slots=True)
class ErrorPresentation:
    title: str
    message: str
    technical_detail: str


def present_error(error: Exception, catalog: Catalog) -> ErrorPresentation:
    if isinstance(error, RepositoryLoadError):
        key = "github"
    elif isinstance(error, UnsafeArchiveError):
        key = "archive"
    elif isinstance(error, AIUnavailableError):
        key = "ai"
    elif isinstance(error, NoScannableFilesError):
        key = "no_sources"
    elif isinstance(error, InputError) and _looks_like_limit_error(str(error)):
        key = "limit"
    elif isinstance(error, InputError):
        key = "input"
    else:
        key = "generic"
    return ErrorPresentation(
        title=catalog.text(f"error.{key}.title"),
        message=catalog.text(f"error.{key}.message"),
        technical_detail=redact_text(str(error))[:2_000] or error.__class__.__name__,
    )


def _looks_like_limit_error(message: str) -> bool:
    value = message.casefold()
    return any(word in value for word in ("limit", "too large", "too many", "exceed"))
