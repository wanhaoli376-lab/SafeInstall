"""Validate and assemble SafeInstall release metadata.

This module intentionally uses only the Python standard library so release
validation does not add another executable dependency to the trusted path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tomllib
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


class ReleaseValidationError(ValueError):
    """Raised when release inputs do not satisfy the publication contract."""


_ALPHA_VERSION = re.compile(r"^(?P<base>\d+\.\d+\.\d+)a(?P<serial>\d+)$")
_RUNTIME_VERSION = re.compile(
    r'^__version__\s*=\s*["\'](?P<version>[^"\']+)["\']\s*$', re.MULTILINE
)
_CHECKSUM_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<name>[^/\\]+)$")
_CONSTRAINT_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+)(?:\s*;.*)?$"
)

WINDOWS_ASSET = "SafeInstall-Windows-x64.zip"
MACOS_ASSET = "SafeInstall-macOS-unsigned.zip"
CHECKSUM_ASSET = "SHA256SUMS.txt"
SBOM_ASSET = "SBOM.json"
ARCHIVE_ASSETS = (WINDOWS_ASSET, MACOS_ASSET)
EXPECTED_RELEASE_ASSETS = (*ARCHIVE_ASSETS, CHECKSUM_ASSET, SBOM_ASSET)
_REQUIRED_ARCHIVE_MEMBERS = {
    WINDOWS_ASSET: "SafeInstall/SafeInstall.exe",
    MACOS_ASSET: "SafeInstall.app/Contents/MacOS/SafeInstall",
}
_ALLOWED_ARCHIVE_ROOTS = {
    WINDOWS_ASSET: ("SafeInstall",),
    MACOS_ASSET: ("SafeInstall.app", "__MACOSX"),
}
_REQUIRED_SBOM_COMPONENTS = {
    "pyside6",
    "pydantic",
    "httpx",
    "pyyaml",
    "rich",
    "typer",
}
_MAX_RELEASE_ZIP_MEMBERS = 200_000
_MAX_RELEASE_ZIP_UNCOMPRESSED = 8 * 1024 * 1024 * 1024
_MAX_CONSTRAINTS_BYTES = 256 * 1024
RELEASE_CONSTRAINTS = Path("constraints/release-python311.txt")


def github_tag_for_version(version: str) -> str:
    """Return the GitHub alpha tag corresponding to a PEP 440 version."""
    match = _ALPHA_VERSION.fullmatch(version)
    if match is None:
        raise ReleaseValidationError(f"Unsupported alpha package version: {version!r}")
    return f"v{match.group('base')}-alpha.{match.group('serial')}"


def validate_project_version(root: Path, tag: str | None = None) -> str:
    """Validate the package, runtime, and optional Git tag versions."""
    root = Path(root)
    with (root / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)
    package_version = project.get("project", {}).get("version")
    if not isinstance(package_version, str):
        raise ReleaseValidationError("pyproject.toml has no string project version")

    runtime_source = (root / "src" / "safeinstall" / "__init__.py").read_text(encoding="utf-8")
    runtime_match = _RUNTIME_VERSION.search(runtime_source)
    if runtime_match is None:
        raise ReleaseValidationError("Runtime version declaration was not found")
    runtime_version = runtime_match.group("version")
    if runtime_version != package_version:
        raise ReleaseValidationError(
            "Runtime version does not match pyproject.toml: "
            f"{runtime_version!r} != {package_version!r}"
        )

    expected_tag = github_tag_for_version(package_version)
    if tag is not None and tag != expected_tag:
        raise ReleaseValidationError(
            f"Git tag {tag!r} does not match package version; expected {expected_tag!r}"
        )
    return package_version


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ReleaseValidationError(f"Required release asset is missing: {path.name}")
    if path.stat().st_size <= 0:
        raise ReleaseValidationError(f"Release asset is empty: {path.name}")


def _validate_release_zip(path: Path) -> None:
    _require_regular_file(path)
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > _MAX_RELEASE_ZIP_MEMBERS:
                raise ReleaseValidationError(f"Release archive has too many members: {path.name}")
            total_size = sum(member.file_size for member in members)
            if total_size > _MAX_RELEASE_ZIP_UNCOMPRESSED:
                raise ReleaseValidationError(
                    f"Release archive expands beyond the validation limit: {path.name}"
                )

            allowed_roots = _ALLOWED_ARCHIVE_ROOTS[path.name]
            seen: set[str] = set()
            for member in members:
                parts = _safe_release_member_parts(member.filename, allowed_roots)
                canonical = "/".join(
                    unicodedata.normalize("NFC", part).casefold() for part in parts
                )
                if canonical in seen:
                    raise ReleaseValidationError(
                        f"Release archive has a duplicate or case-colliding member: {path.name}"
                    )
                seen.add(canonical)
                if _zip_member_is_symlink(member):
                    _validate_release_symlink(archive, member, parts, parts[0])

            if archive.testzip() is not None:
                raise ReleaseValidationError(f"Release archive is corrupt: {path.name}")
            required_member = _REQUIRED_ARCHIVE_MEMBERS[path.name]
            required_info = next(
                (member for member in members if member.filename == required_member), None
            )
            if (
                required_info is None
                or required_info.is_dir()
                or _zip_member_is_symlink(required_info)
            ):
                raise ReleaseValidationError(
                    f"Release archive {path.name} is missing {required_member}"
                )
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ReleaseValidationError(f"Release archive cannot be read: {path.name}") from error


def _safe_release_member_parts(name: str, allowed_roots: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not name
        or len(name) > 4096
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ReleaseValidationError(f"Release archive has an unsafe member: {name!r}")
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    parts = tuple(part for part in posix.parts if part not in ("", "."))
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or not parts
        or ".." in parts
        or parts[0] not in allowed_roots
        or any(_unsafe_windows_path_part(part) for part in parts)
    ):
        raise ReleaseValidationError(f"Release archive has an unsafe member: {name!r}")
    return parts


def _unsafe_windows_path_part(part: str) -> bool:
    if ":" in part or len(part) > 255 or part.endswith((" ", ".")):
        return True
    basename = part.split(".", maxsplit=1)[0].casefold()
    if basename in {"con", "prn", "aux", "nul"}:
        return True
    return bool(re.fullmatch(r"(?:com|lpt)[1-9]", basename))


def _zip_member_is_symlink(member: zipfile.ZipInfo) -> bool:
    unix_mode = (member.external_attr >> 16) & 0xFFFF
    return member.create_system == 3 and stat.S_ISLNK(unix_mode)


def _validate_release_symlink(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    member_parts: tuple[str, ...],
    expected_root: str,
) -> None:
    if member.file_size > 4096:
        raise ReleaseValidationError(
            f"Release archive symlink target is too large: {member.filename}"
        )
    try:
        target = archive.read(member).decode("utf-8")
    except (UnicodeDecodeError, RuntimeError) as error:
        raise ReleaseValidationError(
            f"Release archive symlink target is invalid: {member.filename}"
        ) from error
    if (
        not target
        or "\\" in target
        or PurePosixPath(target).is_absolute()
        or PureWindowsPath(target).is_absolute()
        or PureWindowsPath(target).drive
        or any(ord(character) < 32 or ord(character) == 127 for character in target)
    ):
        raise ReleaseValidationError(f"Release archive has an unsafe symlink: {member.filename}")

    resolved = list(member_parts[:-1])
    for part in PurePosixPath(target).parts:
        if part in ("", "."):
            continue
        if part == "..":
            if len(resolved) <= 1:
                raise ReleaseValidationError(
                    f"Release archive symlink escapes its root: {member.filename}"
                )
            resolved.pop()
        else:
            resolved.append(part)
    if not resolved or resolved[0] != expected_root:
        raise ReleaseValidationError(f"Release archive symlink escapes its root: {member.filename}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def generate_checksums(directory: Path) -> Path:
    """Validate final ZIPs and create a checksum file without overwriting one."""
    directory = Path(directory)
    lines: list[str] = []
    for name in ARCHIVE_ASSETS:
        path = directory / name
        _validate_release_zip(path)
        lines.append(f"{_sha256(path)}  {name}")

    output = directory / CHECKSUM_ASSET
    try:
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines) + "\n")
    except FileExistsError as error:
        raise ReleaseValidationError(f"Refusing to overwrite existing {CHECKSUM_ASSET}") from error
    return output


def verify_checksums(directory: Path) -> None:
    """Verify the exact release ZIP names against SHA256SUMS.txt."""
    directory = Path(directory)
    checksum_path = directory / CHECKSUM_ASSET
    _require_regular_file(checksum_path)
    if checksum_path.stat().st_size > 4096:
        raise ReleaseValidationError(f"{CHECKSUM_ASSET} is unexpectedly large")

    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != len(ARCHIVE_ASSETS):
        raise ReleaseValidationError(
            f"{CHECKSUM_ASSET} must contain exactly {len(ARCHIVE_ASSETS)} entries"
        )

    parsed: dict[str, str] = {}
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ReleaseValidationError(f"Malformed checksum entry: {line!r}")
        name = match.group("name")
        if name in parsed:
            raise ReleaseValidationError(f"Duplicate checksum entry: {name}")
        parsed[name] = match.group("digest")

    if tuple(parsed) != ARCHIVE_ASSETS:
        raise ReleaseValidationError(
            f"Checksum assets must be exactly: {', '.join(ARCHIVE_ASSETS)}"
        )
    for name, expected in parsed.items():
        path = directory / name
        _require_regular_file(path)
        actual = _sha256(path)
        if actual != expected:
            raise ReleaseValidationError(f"SHA-256 mismatch for {name}")


def _normalise_component_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_constraint_versions(path: Path) -> dict[str, str]:
    path = Path(path)
    _require_regular_file(path)
    if path.stat().st_size > _MAX_CONSTRAINTS_BYTES:
        raise ReleaseValidationError("Release constraints file is unexpectedly large")
    versions: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ReleaseValidationError("Release constraints file cannot be read") from error
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _CONSTRAINT_PIN.fullmatch(line)
        if match is None:
            raise ReleaseValidationError(
                f"Release constraint is not an exact pin at line {line_number}"
            )
        name = _normalise_component_name(match.group("name"))
        if name in versions:
            raise ReleaseValidationError(f"Duplicate release constraint: {name}")
        versions[name] = match.group("version")
    return versions


def validate_sbom(path: Path, version: str, constraints_path: Path) -> None:
    """Validate the release's CycloneDX Python-runtime SBOM contract."""
    path = Path(path)
    _require_regular_file(path)
    if path.stat().st_size > 20 * 1024 * 1024:
        raise ReleaseValidationError(f"{SBOM_ASSET} is unexpectedly large")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseValidationError(f"{SBOM_ASSET} is not valid JSON") from error
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ReleaseValidationError(f"{SBOM_ASSET} is not a CycloneDX document")
    if document.get("specVersion") != "1.6":
        raise ReleaseValidationError(f"{SBOM_ASSET} must use CycloneDX 1.6")

    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        raise ReleaseValidationError("SBOM has no root SafeInstall component")
    if str(component.get("name", "")).casefold() != "safeinstall":
        raise ReleaseValidationError("SBOM root component is not SafeInstall")
    if component.get("version") != version:
        raise ReleaseValidationError(
            f"SBOM product version does not match package version {version!r}"
        )

    raw_components = document.get("components")
    if not isinstance(raw_components, list):
        raise ReleaseValidationError("SBOM components must be a list")
    components: dict[str, str] = {}
    for item in raw_components:
        if not isinstance(item, dict):
            raise ReleaseValidationError("SBOM contains a malformed component")
        name_value = item.get("name")
        version_value = item.get("version")
        if (
            not isinstance(name_value, str)
            or not name_value.strip()
            or not isinstance(version_value, str)
            or not version_value.strip()
        ):
            raise ReleaseValidationError("SBOM component name and version must be strings")
        name = _normalise_component_name(name_value)
        if name in components:
            raise ReleaseValidationError(f"SBOM contains a duplicate component: {name}")
        components[name] = version_value

    missing = _REQUIRED_SBOM_COMPONENTS - components.keys()
    if missing:
        raise ReleaseValidationError(
            "SBOM is missing required runtime components: " + ", ".join(sorted(missing))
        )
    if "openai" in components:
        raise ReleaseValidationError("OpenAI SDK must not be included in the portable release SBOM")

    constraints = _read_constraint_versions(constraints_path)
    for name in sorted(_REQUIRED_SBOM_COMPONENTS):
        expected_version = constraints.get(name)
        if expected_version is None:
            raise ReleaseValidationError(f"Release constraints are missing {name}")
        if components[name] != expected_version:
            raise ReleaseValidationError(
                f"SBOM version for {name} does not match release constraints: "
                f"{components[name]!r} != {expected_version!r}"
            )


def verify_release_assets(directory: Path, version: str, constraints_path: Path) -> None:
    """Verify that a directory contains exactly the four publishable assets."""
    directory = Path(directory)
    if not directory.is_dir():
        raise ReleaseValidationError(f"Release asset directory is missing: {directory}")
    actual = {entry.name for entry in directory.iterdir() if entry.is_file() or entry.is_symlink()}
    expected = set(EXPECTED_RELEASE_ASSETS)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ReleaseValidationError(
            "Release directory must contain exactly the expected assets; "
            f"missing={missing}, unexpected={unexpected}"
        )
    for name in ARCHIVE_ASSETS:
        _validate_release_zip(directory / name)
    verify_checksums(directory)
    validate_sbom(directory / SBOM_ASSET, version, constraints_path)


def validate_release_metadata(path: Path, *, tag: str, expected_draft: bool) -> None:
    """Validate GitHub's release JSON before and after publication."""
    path = Path(path)
    _require_regular_file(path)
    if path.stat().st_size > 1024 * 1024:
        raise ReleaseValidationError("GitHub release metadata is unexpectedly large")
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseValidationError("GitHub release metadata is not valid JSON") from error
    if not isinstance(metadata, dict):
        raise ReleaseValidationError("GitHub release metadata must be an object")
    if metadata.get("tagName") != tag:
        raise ReleaseValidationError("GitHub release tag does not match the requested tag")
    if metadata.get("isPrerelease") is not True:
        raise ReleaseValidationError("GitHub release must be a prerelease")
    if metadata.get("isDraft") is not expected_draft:
        raise ReleaseValidationError(f"GitHub release draft state must be {expected_draft}")

    raw_assets = metadata.get("assets")
    if not isinstance(raw_assets, list):
        raise ReleaseValidationError("GitHub release assets must be a list")
    names = [
        item.get("name")
        for item in raw_assets
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    if len(names) != len(raw_assets) or len(names) != len(set(names)):
        raise ReleaseValidationError("GitHub release assets are malformed or duplicated")
    if set(names) != set(EXPECTED_RELEASE_ASSETS):
        raise ReleaseValidationError("GitHub release assets do not match the four expected files")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    version = commands.add_parser(
        "validate-version", help="check package, runtime, and tag versions"
    )
    version.add_argument("--root", type=Path, default=Path.cwd())
    version.add_argument("--tag")

    checksums = commands.add_parser(
        "generate-checksums", help="validate final ZIPs and write SHA256SUMS.txt"
    )
    checksums.add_argument("--directory", type=Path, required=True)

    assets = commands.add_parser("verify-assets", help="validate the exact four release assets")
    assets.add_argument("--directory", type=Path, required=True)
    assets.add_argument("--root", type=Path, default=Path.cwd())
    assets.add_argument("--tag")

    release = commands.add_parser("verify-release", help="validate GitHub release JSON metadata")
    release.add_argument("--metadata", type=Path, required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--state", choices=("draft", "published"), required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the release validation command-line interface."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-version":
            version = validate_project_version(args.root, args.tag)
            print(f"Validated SafeInstall {version} ({github_tag_for_version(version)})")
        elif args.command == "generate-checksums":
            path = generate_checksums(args.directory)
            print(f"Created {path}")
        elif args.command == "verify-assets":
            version = validate_project_version(args.root, args.tag)
            verify_release_assets(args.directory, version, args.root / RELEASE_CONSTRAINTS)
            print("Validated the four release assets")
        elif args.command == "verify-release":
            validate_release_metadata(
                args.metadata,
                tag=args.tag,
                expected_draft=args.state == "draft",
            )
            print(f"Validated {args.state} GitHub prerelease metadata")
        else:  # pragma: no cover - argparse requires one of the commands
            parser.error("unknown command")
    except ReleaseValidationError as error:
        parser.exit(1, f"release validation failed: {error}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by workflow commands
    raise SystemExit(main())
