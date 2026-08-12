"""Bounded archive extraction that rejects traversal and link entries."""

from __future__ import annotations

import stat
import tarfile
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from tempfile import TemporaryDirectory
from typing import BinaryIO
from zipfile import BadZipFile, ZipFile, ZipInfo

from safeinstall.exceptions import InputError, UnsafeArchiveError
from safeinstall.loaders.base import LoadedTarget
from safeinstall.models import TargetKind


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_members: int = 10_000
    max_file_bytes: int = 25_000_000
    max_total_bytes: int = 250_000_000
    max_compression_ratio: int = 200


class ArchiveLoader:
    """Extract supported archives without trusting member paths or metadata."""

    def __init__(
        self,
        *,
        limits: ArchiveLimits | None = None,
        temp_parent: Path | None = None,
    ) -> None:
        self._limits = limits or ArchiveLimits()
        self._temp_parent = temp_parent

    def supports(self, target: str) -> bool:
        lower = target.casefold()
        return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz"))

    @contextmanager
    def open(self, target: str | Path) -> Iterator[LoadedTarget]:
        archive = Path(target).expanduser()
        if not archive.is_file():
            raise InputError(f"Archive does not exist or is not a file: {archive}")
        if not self.supports(archive.name):
            raise InputError(f"Unsupported archive format: {archive.name}")

        temp_parent = str(self._temp_parent) if self._temp_parent is not None else None
        with TemporaryDirectory(prefix="safeinstall-archive-", dir=temp_parent) as temp_name:
            root = Path(temp_name) / "content"
            root.mkdir()
            if archive.name.casefold().endswith(".zip"):
                self._extract_zip(archive, root)
            else:
                self._extract_tar(archive, root)
            yield LoadedTarget(
                root=root,
                source=str(archive),
                kind=TargetKind.ARCHIVE,
                metadata={"archive": archive.name},
            )

    def _extract_zip(self, archive: Path, root: Path) -> None:
        try:
            with ZipFile(archive) as zip_file:
                entries = self._validate_zip(zip_file.infolist())
                total_copied = 0
                for info, relative in entries:
                    destination = root.joinpath(*relative.parts)
                    if info.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with zip_file.open(info) as source, destination.open("xb") as output:
                        total_copied += self._copy_bounded(
                            source,
                            output,
                            info.filename,
                            remaining_total=self._limits.max_total_bytes - total_copied,
                        )
        except UnsafeArchiveError:
            raise
        except (BadZipFile, OSError, RuntimeError, ValueError) as exc:
            raise UnsafeArchiveError(f"Could not safely read ZIP archive {archive}: {exc}") from exc

    def _extract_tar(self, archive: Path, root: Path) -> None:
        try:
            with tarfile.open(archive, mode="r:*") as tar_file:
                entries = self._validate_tar(
                    tar_file.getmembers(), compressed_bytes=archive.stat().st_size
                )
                total_copied = 0
                for info, relative in entries:
                    destination = root.joinpath(*relative.parts)
                    if info.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    source = tar_file.extractfile(info)
                    if source is None:
                        raise UnsafeArchiveError(f"Could not read archive member: {info.name!r}")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with source, destination.open("xb") as output:
                        total_copied += self._copy_bounded(
                            source,
                            output,
                            info.name,
                            remaining_total=self._limits.max_total_bytes - total_copied,
                        )
        except UnsafeArchiveError:
            raise
        except (tarfile.TarError, OSError, RuntimeError, ValueError) as exc:
            raise UnsafeArchiveError(f"Could not safely read TAR archive {archive}: {exc}") from exc

    def _validate_zip(self, infos: list[ZipInfo]) -> list[tuple[ZipInfo, PurePosixPath]]:
        if len(infos) > self._limits.max_members:
            raise UnsafeArchiveError("Archive contains too many members.")

        total_size = 0
        seen: set[str] = set()
        validated: list[tuple[ZipInfo, PurePosixPath]] = []
        for info in infos:
            relative = _safe_member_path(info.filename)
            collision_key = _collision_key(relative)
            if collision_key in seen:
                raise UnsafeArchiveError(f"Archive contains a duplicate path: {info.filename!r}")
            seen.add(collision_key)
            if _zip_is_link(info):
                raise UnsafeArchiveError(f"Archive links are not allowed: {info.filename!r}")
            if info.file_size > self._limits.max_file_bytes:
                raise UnsafeArchiveError(f"Archive member is too large: {info.filename!r}")
            total_size += info.file_size
            if total_size > self._limits.max_total_bytes:
                raise UnsafeArchiveError("Archive expands beyond the total size limit.")
            if info.file_size and (
                info.compress_size == 0
                or info.file_size / info.compress_size > self._limits.max_compression_ratio
            ):
                raise UnsafeArchiveError(
                    f"Archive member exceeds the compression ratio limit: {info.filename!r}"
                )
            validated.append((info, relative))
        return validated

    def _validate_tar(
        self, infos: list[tarfile.TarInfo], *, compressed_bytes: int
    ) -> list[tuple[tarfile.TarInfo, PurePosixPath]]:
        if len(infos) > self._limits.max_members:
            raise UnsafeArchiveError("Archive contains too many members.")

        total_size = 0
        seen: set[str] = set()
        validated: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
        for info in infos:
            relative = _safe_member_path(info.name)
            collision_key = _collision_key(relative)
            if collision_key in seen:
                raise UnsafeArchiveError(f"Archive contains a duplicate path: {info.name!r}")
            seen.add(collision_key)
            if info.issym() or info.islnk():
                raise UnsafeArchiveError(f"Archive links are not allowed: {info.name!r}")
            if not (info.isfile() or info.isdir()):
                raise UnsafeArchiveError(f"Archive member type is not allowed: {info.name!r}")
            if info.size > self._limits.max_file_bytes:
                raise UnsafeArchiveError(f"Archive member is too large: {info.name!r}")
            total_size += info.size
            if total_size > self._limits.max_total_bytes:
                raise UnsafeArchiveError("Archive expands beyond the total size limit.")
            validated.append((info, relative))

        if total_size and (
            compressed_bytes == 0
            or total_size / compressed_bytes > self._limits.max_compression_ratio
        ):
            raise UnsafeArchiveError("Archive exceeds the compression ratio limit.")
        return validated

    def _copy_bounded(
        self,
        source: BinaryIO,
        output: BinaryIO,
        member_name: str,
        *,
        remaining_total: int,
    ) -> int:
        copied = 0
        while True:
            chunk = source.read(64 * 1024)
            if not chunk:
                return copied
            copied += len(chunk)
            if copied > self._limits.max_file_bytes:
                raise UnsafeArchiveError(f"Archive member is too large: {member_name!r}")
            if copied > remaining_total:
                raise UnsafeArchiveError("Archive expands beyond the total size limit.")
            output.write(chunk)


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or len(name) > 4096:
        raise UnsafeArchiveError(f"Archive member has unsafe path: {name!r}")
    normalized = name.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(normalized)
    if (
        not posix_path.parts
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or any(part in {"", ".", ".."} for part in posix_path.parts)
        or any(_unsafe_path_part(part) for part in posix_path.parts)
    ):
        raise UnsafeArchiveError(f"Archive member has unsafe path: {name!r}")
    return posix_path


def _unsafe_path_part(part: str) -> bool:
    if len(part) > 255 or part.endswith((" ", ".")) or ":" in part:
        return True
    if any(ord(character) < 32 or ord(character) == 127 for character in part):
        return True
    basename = part.split(".", 1)[0].casefold()
    reserved = {"con", "prn", "aux", "nul"}
    reserved.update(f"com{number}" for number in range(1, 10))
    reserved.update(f"lpt{number}" for number in range(1, 10))
    return basename in reserved


def _collision_key(path: PurePosixPath) -> str:
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in path.parts)


def _zip_is_link(info: ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)
