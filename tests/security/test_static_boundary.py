from pathlib import Path

from safeinstall.core import scan_target


def test_scan_does_not_execute_or_import_target_python(tmp_path: Path) -> None:
    marker = tmp_path / "target-code-ran.txt"
    project = tmp_path / "target"
    project.mkdir()
    (project / "setup.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('target code ran', encoding='utf-8')\n",
        encoding="utf-8",
    )

    report = scan_target(project)

    assert report.target.files_scanned == 1
    assert not marker.exists()
