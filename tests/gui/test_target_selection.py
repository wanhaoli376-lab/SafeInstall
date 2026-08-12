from pathlib import Path

import pytest

pytest.importorskip("PySide6")

from safeinstall.gui.models import TargetType
from safeinstall.gui.targeting import classify_target


def test_classifies_supported_local_targets(tmp_path: Path) -> None:
    source = tmp_path / "check.py"
    source.write_text("print('inert fixture')", encoding="utf-8")
    archive = tmp_path / "project.tar.gz"
    archive.touch()

    file_selection = classify_target(str(source))
    folder_selection = classify_target(str(tmp_path))
    archive_selection = classify_target(str(archive))

    assert file_selection.supported and file_selection.kind is TargetType.FILE
    assert folder_selection.supported and folder_selection.kind is TargetType.FOLDER
    assert archive_selection.supported and archive_selection.kind is TargetType.ARCHIVE


def test_classifies_github_without_using_network() -> None:
    selection = classify_target("https://github.com/owner/repository")

    assert selection.supported
    assert selection.kind is TargetType.GITHUB
    assert selection.display_name == "owner/repository"


@pytest.mark.parametrize("filename", ["program.exe", "installer.msi", "disk.dmg", "app.pkg"])
def test_rejects_binary_targets_that_are_not_analyzed(tmp_path: Path, filename: str) -> None:
    target = tmp_path / filename
    target.touch()

    selection = classify_target(str(target))

    assert not selection.supported
    assert selection.kind is TargetType.UNSUPPORTED
    assert selection.reason == "unsupported_binary"


def test_rejects_unknown_file_format(tmp_path: Path) -> None:
    target = tmp_path / "payload.bin"
    target.touch()

    selection = classify_target(str(target))

    assert not selection.supported
    assert selection.reason == "unsupported_file"


def test_untrusted_filename_controls_are_visible_but_raw_target_is_preserved(
    tmp_path: Path,
) -> None:
    target = tmp_path / "report\u202e.py"
    target.touch()

    selection = classify_target(str(target))

    assert selection.target == str(target)
    assert "\u202e" not in selection.display_name
    assert "\\u202e" in selection.display_name
