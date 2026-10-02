"""Bounded discovery and decoding of untrusted text files."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from safeinstall.exceptions import InputError
from safeinstall.loaders.base import LoadedTarget
from safeinstall.loaders.local import _is_link_or_reparse
from safeinstall.models import (
    MAX_RECORDED_SKIPS,
    ScanCoverage,
    SkippedPath,
    SkipReason,
    SourceFile,
)
from safeinstall.redaction import redact_text


@dataclass(frozen=True, slots=True)
class DiscoveryLimits:
    max_entries: int = 100_000
    max_files: int = 20_000
    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 100_000_000


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    sources: tuple[SourceFile, ...]
    coverage: ScanCoverage


_IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vendor",
    "venv",
}

_LANGUAGE_BY_SUFFIX = {
    ".bat": "batch",
    ".bash": "shell",
    ".cjs": "javascript",
    ".cmd": "batch",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "javascript",
    ".md": "markdown",
    ".mjs": "javascript",
    ".ps1": "powershell",
    ".py": "python",
    ".sh": "shell",
    ".toml": "toml",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".txt": "text",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".zsh": "shell",
}

_SPECIAL_TEXT_FILES = {
    "dockerfile": "dockerfile",
    "gemfile": "text",
    "makefile": "makefile",
    "pipfile": "toml",
    "procfile": "text",
    "requirements.txt": "text",
}


class FileDiscoverer:
    """Return decodable source files while containing traversal and resource use."""

    def __init__(self, *, limits: DiscoveryLimits | None = None) -> None:
        self._limits = limits or DiscoveryLimits()

    @staticmethod
    def supports_file(path: Path) -> bool:
        """Return whether a single local file has a supported text format."""

        return _detect_language(path, path.parent) is not None

    def discover(self, target: LoadedTarget) -> tuple[SourceFile, ...]:
        """Compatibility adapter for callers that only need loaded source content."""

        return self.discover_with_coverage(target).sources

    def discover_with_coverage(self, target: LoadedTarget) -> DiscoveryResult:
        root = target.root.resolve(strict=True)
        skipped: list[SkippedPath] = []
        skipped_count = 0

        def record_skip(path: Path, reason: SkipReason) -> None:
            nonlocal skipped_count
            skipped_count += 1
            if len(skipped) < MAX_RECORDED_SKIPS:
                relative = path.relative_to(root).as_posix() if path.is_relative_to(root) else "."
                skipped.append(SkippedPath(path=redact_text(relative), reason=reason))

        candidates = (
            self._selected_candidates(root, target.selected_files)
            if target.selected_files is not None
            else self._walk_candidates(root, record_skip)
        )
        sources: list[SourceFile] = []
        total_bytes = 0
        for path in candidates:
            language = _detect_language(path, root)
            if language is None:
                continue
            try:
                if _is_link_or_reparse(path):
                    record_skip(path, SkipReason.UNSAFE_PATH)
                    continue
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root) or not resolved.is_file():
                    record_skip(path, SkipReason.UNSAFE_PATH)
                    continue
                with resolved.open("rb") as stream:
                    raw = stream.read(self._limits.max_file_bytes + 1)
            except (OSError, RuntimeError):
                record_skip(path, SkipReason.UNREADABLE)
                continue
            if len(raw) > self._limits.max_file_bytes:
                record_skip(path, SkipReason.FILE_TOO_LARGE)
                continue
            total_bytes += len(raw)
            if total_bytes > self._limits.max_total_bytes:
                raise InputError("Target text files exceed the total scan size limit.")
            content = _decode_text(raw)
            if content is None:
                record_skip(path, SkipReason.UNDECODABLE_TEXT)
                continue
            relative = resolved.relative_to(root).as_posix()
            sources.append(SourceFile(path=relative, language=language, content=content))
            if len(sources) > self._limits.max_files:
                raise InputError("Target contains more scannable files than the configured limit.")
        return DiscoveryResult(
            sources=tuple(sources),
            coverage=ScanCoverage(
                status="partial" if skipped_count else "complete",
                skipped_count=skipped_count,
                skipped_paths=tuple(skipped),
            ),
        )

    def _selected_candidates(self, root: Path, selected: tuple[Path, ...]) -> list[Path]:
        candidates: list[Path] = []
        for relative in selected:
            if relative.is_absolute() or ".." in relative.parts:
                raise InputError(f"Selected file escapes target root: {relative}")
            candidates.append(root / relative)
        return sorted(candidates, key=lambda path: path.relative_to(root).as_posix())

    def _walk_candidates(
        self, root: Path, record_skip: Callable[[Path, SkipReason], None]
    ) -> list[Path]:
        candidates: list[Path] = []
        entries = 0

        def walk_error(error: OSError) -> None:
            path = Path(os.fsdecode(error.filename)) if error.filename is not None else root
            record_skip(path, SkipReason.UNREADABLE)

        for current, directories, filenames in os.walk(
            root, topdown=True, followlinks=False, onerror=walk_error
        ):
            current_path = Path(current)
            entries += len(directories) + len(filenames)
            if entries > self._limits.max_entries:
                raise InputError(
                    "Target contains more directory entries than the configured limit."
                )
            allowed_directories: list[str] = []
            for name in sorted(directories, key=str.casefold):
                if name.casefold() in _IGNORED_DIRECTORIES:
                    continue
                path = current_path / name
                try:
                    if _is_link_or_reparse(path):
                        record_skip(path, SkipReason.UNSAFE_PATH)
                    else:
                        allowed_directories.append(name)
                except OSError:
                    record_skip(path, SkipReason.UNREADABLE)
            directories[:] = allowed_directories
            for filename in sorted(filenames):
                candidates.append(current_path / filename)
        return candidates


def _detect_language(path: Path, root: Path) -> str | None:
    name = path.name.casefold()
    if name == ".env" or name.startswith(".env."):
        return "text"
    if name in _SPECIAL_TEXT_FILES:
        return _SPECIAL_TEXT_FILES[name]
    language = _LANGUAGE_BY_SUFFIX.get(path.suffix.casefold())
    if language == "yaml":
        relative_parts = tuple(part.casefold() for part in path.relative_to(root).parts)
        if len(relative_parts) >= 3 and relative_parts[:2] == (".github", "workflows"):
            return "github-actions"
    return language


def _decode_text(raw: bytes) -> str | None:
    if b"\x00" in raw[:8192] and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return None
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
