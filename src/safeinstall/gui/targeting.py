"""Side-effect-free target classification for desktop input controls."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from safeinstall.gui.models import TargetSelection, TargetType
from safeinstall.loaders.archive import ArchiveLoader
from safeinstall.loaders.discovery import FileDiscoverer
from safeinstall.loaders.github import GitHubLoader
from safeinstall.redaction import redact_text

_UNSUPPORTED_BINARY_SUFFIXES = {".dmg", ".exe", ".msi", ".pkg"}


def classify_target(target: str) -> TargetSelection:
    """Classify a user choice without opening it, scanning it, or using the network."""

    value = target.strip()
    if not value:
        return _unsupported(value, "invalid_target")
    if GitHubLoader().supports(value):
        parts = urlsplit(value).path.removesuffix("/").removesuffix(".git").strip("/")
        return TargetSelection(
            target=value,
            display_name=redact_text(parts),
            kind=TargetType.GITHUB,
            location=redact_text(value),
            supported=True,
        )
    if value.casefold().startswith(("http://", "https://")):
        return _unsupported(value, "invalid_github")

    try:
        path = Path(value).expanduser()
        if not path.exists():
            return _unsupported(value, "missing_target")
        location = str(path.absolute())
        if path.is_dir():
            return TargetSelection(
                target=str(path),
                display_name=redact_text(path.name or location),
                kind=TargetType.FOLDER,
                location=redact_text(location),
                supported=True,
            )
        if not path.is_file():
            return _unsupported(value, "unsupported_file")
        if ArchiveLoader().supports(path.name):
            kind = TargetType.ARCHIVE
        elif FileDiscoverer.supports_file(path):
            kind = TargetType.FILE
        else:
            reason = (
                "unsupported_binary"
                if path.suffix.casefold() in _UNSUPPORTED_BINARY_SUFFIXES
                else "unsupported_file"
            )
            return _unsupported(
                value,
                reason,
                display_name=redact_text(path.name),
                location=redact_text(location),
            )
        return TargetSelection(
            target=str(path),
            display_name=redact_text(path.name),
            kind=kind,
            location=redact_text(location),
            supported=True,
        )
    except (OSError, ValueError):
        return _unsupported(value, "invalid_target")


def _unsupported(
    target: str,
    reason: str,
    *,
    display_name: str | None = None,
    location: str | None = None,
) -> TargetSelection:
    return TargetSelection(
        target=target,
        display_name=redact_text(display_name or Path(target).name or target or "—"),
        kind=TargetType.UNSUPPORTED,
        location=redact_text(location or target or "—"),
        supported=False,
        reason=reason,
    )
