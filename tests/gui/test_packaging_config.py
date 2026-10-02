import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from safeinstall.gui.app import main


def test_desktop_smoke_mode_creates_and_closes_window() -> None:
    assert main(["safeinstall-gui", "--smoke-test", "-platform", "offscreen"]) == 0


def test_desktop_smoke_scan_uses_real_core_without_ai() -> None:
    target = Path(__file__).parents[2] / "examples" / "risky-project"

    assert (
        main(
            [
                "safeinstall-gui",
                "--smoke-scan",
                str(target),
                "-platform",
                "offscreen",
            ]
        )
        == 0
    )


def test_windows_portable_spec_is_one_folder_and_excludes_optional_ai_sdk() -> None:
    root = Path(__file__).parents[2]
    spec = (root / "packaging" / "safeinstall.spec").read_text(encoding="utf-8")

    assert "COLLECT(" in spec
    assert "exclude_binaries=True" in spec
    assert 'excludes=["openai"]' in spec
    assert "console=False" in spec
    assert "collect_data_files" in spec


def test_spec_creates_macos_app_bundle_only_on_macos() -> None:
    root = Path(__file__).parents[2]
    spec = (root / "packaging" / "safeinstall.spec").read_text(encoding="utf-8")

    assert 'sys.platform == "darwin"' in spec
    assert "BUNDLE(" in spec
    assert 'name="SafeInstall.app"' in spec
    assert 'bundle_identifier="io.github.wanhaoli376-lab.safeinstall"' in spec
    assert "codesign_identity=None" in spec
    assert "validate_project_version(project_root)" in spec
    assert "macos_bundle_versions(package_version)" in spec
    assert '"CFBundleShortVersionString": bundle_short_version' in spec
    assert '"CFBundleVersion": bundle_build_version' in spec
    assert '"SafeInstallPackageVersion": package_version' in spec
