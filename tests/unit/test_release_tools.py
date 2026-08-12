from __future__ import annotations

import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest
from tools.release import (
    MACOS_ASSET,
    WINDOWS_ASSET,
    ReleaseValidationError,
    generate_checksums,
    github_tag_for_version,
    main,
    validate_project_version,
    validate_release_metadata,
    validate_sbom,
    verify_checksums,
    verify_release_assets,
)


def test_alpha_package_version_maps_to_release_tag() -> None:
    assert github_tag_for_version("0.2.0a1") == "v0.2.0-alpha.1"


def test_repository_version_matches_public_alpha_tag() -> None:
    root = Path(__file__).parents[2]

    assert validate_project_version(root, "v0.2.0-alpha.1") == "0.2.0a1"


@pytest.mark.parametrize("version", ["0.2.0", "0.2.0b1", "0.2.0a", "alpha.1"])
def test_non_alpha_package_versions_are_rejected(version: str) -> None:
    with pytest.raises(ReleaseValidationError):
        github_tag_for_version(version)


def _write_project_versions(tmp_path, package: str, runtime: str) -> None:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "safeinstall"\nversion = "{package}"\n', encoding="utf-8"
    )
    package_dir = tmp_path / "src" / "safeinstall"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text(f'__version__ = "{runtime}"\n', encoding="utf-8")


def test_project_version_and_tag_must_match(tmp_path) -> None:
    _write_project_versions(tmp_path, "0.2.0a1", "0.2.0a1")

    assert validate_project_version(tmp_path, "v0.2.0-alpha.1") == "0.2.0a1"


def test_runtime_version_mismatch_is_rejected(tmp_path) -> None:
    _write_project_versions(tmp_path, "0.2.0a1", "0.2.0a0")

    with pytest.raises(ReleaseValidationError, match="Runtime version"):
        validate_project_version(tmp_path, "v0.2.0-alpha.1")


def test_tag_version_mismatch_is_rejected(tmp_path) -> None:
    _write_project_versions(tmp_path, "0.2.0a1", "0.2.0a1")

    with pytest.raises(ReleaseValidationError, match="tag"):
        validate_project_version(tmp_path, "v0.2.0-alpha.2")


def _write_release_zip(path, member: str, payload: bytes = b"binary") -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(member, payload)


def test_checksums_cover_the_exact_final_zip_assets(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")

    checksum_path = generate_checksums(tmp_path)

    expected_lines = []
    for name in (WINDOWS_ASSET, MACOS_ASSET):
        digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        expected_lines.append(f"{digest}  {name}")
    assert checksum_path.read_text(encoding="utf-8") == "\n".join(expected_lines) + "\n"
    verify_checksums(tmp_path)


def test_checksums_reject_a_missing_release_zip(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")

    with pytest.raises(ReleaseValidationError, match=MACOS_ASSET):
        generate_checksums(tmp_path)


def test_release_zip_rejects_path_traversal_member(tmp_path) -> None:
    with zipfile.ZipFile(tmp_path / WINDOWS_ASSET, "w") as archive:
        archive.writestr("SafeInstall/SafeInstall.exe", b"binary")
        archive.writestr("../outside.txt", b"inert")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")

    with pytest.raises(ReleaseValidationError, match="unsafe member"):
        generate_checksums(tmp_path)


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "/absolute.txt",
        "C:/drive.txt",
        "C:\\drive.txt",
        "//server/share.txt",
        "SafeInstall/CON.txt",
        "SafeInstall/NUL",
        "SafeInstall/COM1.log",
        "SafeInstall/LPT9",
        "SafeInstall/trailing.",
        "SafeInstall/trailing ",
    ],
)
def test_release_zip_rejects_absolute_drive_and_unc_members(tmp_path, unsafe_name) -> None:
    with zipfile.ZipFile(tmp_path / WINDOWS_ASSET, "w") as archive:
        archive.writestr("SafeInstall/SafeInstall.exe", b"binary")
        archive.writestr(unsafe_name, b"inert")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")

    with pytest.raises(ReleaseValidationError, match="unsafe member"):
        generate_checksums(tmp_path)


def test_release_zip_rejects_windows_alias_collision(tmp_path) -> None:
    with zipfile.ZipFile(tmp_path / WINDOWS_ASSET, "w") as archive:
        archive.writestr("SafeInstall/SafeInstall.exe", b"binary")
        archive.writestr("SafeInstall/readme", b"one")
        archive.writestr("SafeInstall/readme.", b"two")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")

    with pytest.raises(ReleaseValidationError, match="unsafe member"):
        generate_checksums(tmp_path)


def test_release_zip_rejects_unicode_and_case_collision(tmp_path) -> None:
    with zipfile.ZipFile(tmp_path / WINDOWS_ASSET, "w") as archive:
        archive.writestr("SafeInstall/SafeInstall.exe", b"binary")
        archive.writestr("SafeInstall/Café.txt", b"one")
        archive.writestr("SafeInstall/CAFE\u0301.TXT", b"two")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")

    with pytest.raises(ReleaseValidationError, match="colliding"):
        generate_checksums(tmp_path)


def test_release_zip_rejects_symlink_escape(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")
    with zipfile.ZipFile(tmp_path / MACOS_ASSET, "w") as archive:
        archive.writestr("SafeInstall.app/Contents/MacOS/SafeInstall", b"binary")
        link = zipfile.ZipInfo("SafeInstall.app/Contents/Frameworks/escape")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "../../../../outside")

    with pytest.raises(ReleaseValidationError, match="symlink"):
        generate_checksums(tmp_path)


def test_macos_zip_allows_safe_ditto_resource_metadata(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")
    with zipfile.ZipFile(tmp_path / MACOS_ASSET, "w") as archive:
        archive.writestr("SafeInstall.app/Contents/MacOS/SafeInstall", b"binary")
        archive.writestr("__MACOSX/SafeInstall.app/._Contents", b"metadata")

    generate_checksums(tmp_path)


def test_checksum_verification_detects_asset_substitution(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")
    generate_checksums(tmp_path)
    with (tmp_path / WINDOWS_ASSET).open("ab") as handle:
        handle.write(b"substituted")

    with pytest.raises(ReleaseValidationError, match="SHA-256 mismatch"):
        verify_checksums(tmp_path)


_SBOM_COMPONENTS = {
    "PySide6": "6.10.3",
    "pydantic": "2.13.4",
    "httpx": "0.28.1",
    "PyYAML": "6.0.3",
    "rich": "14.3.4",
    "typer": "0.27.1",
}


def _write_constraints(tmp_path) -> Path:
    directory = tmp_path / "config"
    directory.mkdir(exist_ok=True)
    path = directory / "release-python311.txt"
    path.write_text(
        "\n".join(
            f"{name}=={component_version}" for name, component_version in _SBOM_COMPONENTS.items()
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _write_sbom(
    tmp_path,
    *,
    version: str = "0.2.0a1",
    spec_version: str = "1.6",
    include_openai=False,
    component_versions: dict[str, str] | None = None,
) -> None:
    versions = component_versions or _SBOM_COMPONENTS
    if include_openai:
        versions = {**versions, "openai": "2.0.0"}
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "metadata": {
            "component": {
                "type": "application",
                "name": "SafeInstall",
                "version": version,
            }
        },
        "components": [
            {"type": "library", "name": name, "version": component_version}
            for name, component_version in versions.items()
        ],
    }
    (tmp_path / "SBOM.json").write_text(json.dumps(document), encoding="utf-8")


def test_sbom_declares_product_and_required_runtime_dependencies(tmp_path) -> None:
    _write_sbom(tmp_path)

    validate_sbom(tmp_path / "SBOM.json", "0.2.0a1", _write_constraints(tmp_path))


def test_sbom_rejects_wrong_product_version(tmp_path) -> None:
    _write_sbom(tmp_path, version="0.2.0a0")

    with pytest.raises(ReleaseValidationError, match="version"):
        validate_sbom(tmp_path / "SBOM.json", "0.2.0a1", _write_constraints(tmp_path))


def test_sbom_rejects_openai_from_portable_runtime(tmp_path) -> None:
    _write_sbom(tmp_path, include_openai=True)

    with pytest.raises(ReleaseValidationError, match="OpenAI"):
        validate_sbom(tmp_path / "SBOM.json", "0.2.0a1", _write_constraints(tmp_path))


def test_sbom_rejects_wrong_cyclonedx_specification(tmp_path) -> None:
    _write_sbom(tmp_path, spec_version="1.5")

    with pytest.raises(ReleaseValidationError, match="CycloneDX 1.6"):
        validate_sbom(tmp_path / "SBOM.json", "0.2.0a1", _write_constraints(tmp_path))


def test_sbom_rejects_dependency_version_mismatch(tmp_path) -> None:
    _write_sbom(tmp_path, component_versions={**_SBOM_COMPONENTS, "httpx": "0.27.0"})

    with pytest.raises(ReleaseValidationError, match="httpx"):
        validate_sbom(tmp_path / "SBOM.json", "0.2.0a1", _write_constraints(tmp_path))


def _write_complete_release_assets(tmp_path) -> None:
    _write_release_zip(tmp_path / WINDOWS_ASSET, "SafeInstall/SafeInstall.exe")
    _write_release_zip(tmp_path / MACOS_ASSET, "SafeInstall.app/Contents/MacOS/SafeInstall")
    _write_sbom(tmp_path)
    generate_checksums(tmp_path)


def test_complete_release_asset_set_is_verified(tmp_path) -> None:
    _write_complete_release_assets(tmp_path)

    verify_release_assets(tmp_path, "0.2.0a1", _write_constraints(tmp_path))


def test_unexpected_release_asset_is_rejected(tmp_path) -> None:
    _write_complete_release_assets(tmp_path)
    (tmp_path / "stale-build.zip").write_bytes(b"stale")

    with pytest.raises(ReleaseValidationError, match="exactly"):
        verify_release_assets(tmp_path, "0.2.0a1", _write_constraints(tmp_path))


def _write_release_metadata(tmp_path, *, draft: bool, assets=None):
    names = assets or [
        WINDOWS_ASSET,
        MACOS_ASSET,
        "SHA256SUMS.txt",
        "SBOM.json",
    ]
    path = tmp_path / "release.json"
    path.write_text(
        json.dumps(
            {
                "tagName": "v0.2.0-alpha.1",
                "isDraft": draft,
                "isPrerelease": True,
                "assets": [{"name": name} for name in names],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("draft", [True, False])
def test_release_metadata_requires_prerelease_and_exact_assets(tmp_path, draft) -> None:
    metadata = _write_release_metadata(tmp_path, draft=draft)

    validate_release_metadata(metadata, tag="v0.2.0-alpha.1", expected_draft=draft)


def test_release_metadata_rejects_missing_asset(tmp_path) -> None:
    metadata = _write_release_metadata(
        tmp_path,
        draft=True,
        assets=[WINDOWS_ASSET, MACOS_ASSET, "SHA256SUMS.txt"],
    )

    with pytest.raises(ReleaseValidationError, match="assets"):
        validate_release_metadata(metadata, tag="v0.2.0-alpha.1", expected_draft=True)


def test_release_cli_validates_the_project_tag(tmp_path, capsys) -> None:
    _write_project_versions(tmp_path, "0.2.0a1", "0.2.0a1")

    assert (
        main(
            [
                "validate-version",
                "--root",
                str(tmp_path),
                "--tag",
                "v0.2.0-alpha.1",
            ]
        )
        == 0
    )
    assert "0.2.0a1" in capsys.readouterr().out
