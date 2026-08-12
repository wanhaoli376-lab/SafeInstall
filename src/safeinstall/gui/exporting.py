"""Safe, renderer-backed report export for the desktop interface."""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path
from tempfile import NamedTemporaryFile

from safeinstall.models import ScanReport
from safeinstall.report.json_report import render_json
from safeinstall.report.markdown import render_markdown


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"


def normalized_export_path(
    destination: str | Path,
    report_format: ReportFormat,
) -> Path:
    """Return a destination with one format-appropriate report suffix."""

    path = Path(destination).expanduser()
    suffix = ".json" if report_format is ReportFormat.JSON else ".md"
    if path.suffix.casefold() in {".json", ".md", ".markdown"}:
        return path.with_suffix(suffix)
    return Path(f"{path}{suffix}")


def export_report(
    report: ScanReport,
    destination: str | Path,
    report_format: ReportFormat,
    *,
    overwrite: bool = False,
) -> Path:
    """Write an already-redacted existing report without following an output symlink."""

    requested = Path(destination).expanduser()
    parent = requested.parent.resolve(strict=True)
    if not parent.is_dir():
        raise NotADirectoryError(parent)
    path = parent / requested.name
    if path.is_symlink():
        raise OSError("Refusing to export through a symbolic link.")
    if path.exists() and not path.is_file():
        raise OSError("Report destination is not a regular file.")
    if path.exists() and not overwrite:
        raise FileExistsError(path)

    rendered = (
        render_json(report) if report_format is ReportFormat.JSON else render_markdown(report)
    )
    if overwrite:
        _atomic_replace(path, rendered)
    else:
        _write_new(path, rendered)
    return path


def _write_new(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, mode="w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)


def _atomic_replace(path: Path, content: str) -> None:
    temporary_name: str | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".safeinstall-report-",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as stream:
            temporary_name = stream.name
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
