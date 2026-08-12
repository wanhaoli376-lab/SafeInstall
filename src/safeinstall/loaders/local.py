"""Read-only adapter for a local directory or single file."""

from __future__ import annotations

import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from safeinstall.exceptions import InputError
from safeinstall.loaders.base import LoadedTarget
from safeinstall.models import TargetKind


class LocalLoader:
    """Expose an existing local target without copying or executing it."""

    def supports(self, target: str) -> bool:
        return not target.casefold().startswith(("http://", "https://"))

    @contextmanager
    def open(self, target: str | Path) -> Iterator[LoadedTarget]:
        path = Path(target).expanduser()
        if not path.exists():
            raise InputError(f"Local target does not exist: {path}")
        if _is_link_or_reparse(path):
            raise InputError(f"Local target cannot be a symbolic link or junction: {path}")

        resolved = path.resolve(strict=True)
        if resolved.is_dir():
            yield LoadedTarget(
                root=resolved,
                source=str(path),
                kind=TargetKind.LOCAL,
            )
            return
        if resolved.is_file():
            yield LoadedTarget(
                root=resolved.parent,
                source=str(path),
                kind=TargetKind.LOCAL,
                selected_files=(Path(resolved.name),),
            )
            return
        raise InputError(f"Local target is not a regular file or directory: {path}")


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)
