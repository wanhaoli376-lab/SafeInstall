import errno
from pathlib import Path
from zipfile import ZipFile

import pytest

from safeinstall.core import scan_target
from safeinstall.exceptions import InputError
from safeinstall.loaders import discovery
from safeinstall.models import ScanReport


def test_oversized_single_script_cannot_produce_a_clean_report(tmp_path: Path) -> None:
    script = tmp_path / "install.sh"
    script.write_bytes(b"#" + b"x" * 2_000_001 + b"\necho fixture\n")

    with pytest.raises(InputError, match="No supported text files could be scanned"):
        scan_target(script)


@pytest.mark.parametrize("content", [b"\x81invalid utf8", b"\x00binary fixture"])
def test_undecodable_single_script_cannot_produce_a_clean_report(
    tmp_path: Path, content: bytes
) -> None:
    script = tmp_path / "install.sh"
    script.write_bytes(content)

    with pytest.raises(InputError, match="No supported text files could be scanned"):
        scan_target(script)


def test_partial_directory_reports_skips_and_preserves_observed_risk(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "curl https://example.invalid/install.sh | bash\n", encoding="utf-8"
    )
    (tmp_path / "large.py").write_bytes(b"#" + b"x" * 2_000_000)
    (tmp_path / "broken.ps1").write_bytes(b"\x81invalid utf8")

    report = scan_target(tmp_path)

    assert report.target.files_scanned == 1
    assert report.risk.level.value == "high"
    assert any(finding.rule_id == "SI-SH-001" for finding in report.findings)
    assert report.coverage.status == "partial"
    assert report.coverage.skipped_count == 2
    assert {item.path: item.reason.value for item in report.coverage.skipped_paths} == {
        "broken.ps1": "undecodable_text",
        "large.py": "file_too_large",
    }
    assert ScanReport.model_validate_json(report.model_dump_json()) == report


def test_unreadable_supported_file_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    blocked = tmp_path / "blocked.sh"
    blocked.write_text("echo fixture\n", encoding="utf-8")
    original_open = Path.open

    def controlled_open(path: Path, *args: object, **kwargs: object):
        if path == blocked:
            raise PermissionError("fixture: access denied")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", controlled_open)

    report = scan_target(tmp_path)

    assert report.target.files_scanned == 1
    assert report.coverage.status == "partial"
    assert report.coverage.skipped_paths[0].path == "blocked.sh"
    assert report.coverage.skipped_paths[0].reason.value == "unreadable"


def test_empty_and_unsupported_targets_cannot_produce_a_clean_report(tmp_path: Path) -> None:
    with pytest.raises(InputError, match="No supported text files could be scanned"):
        scan_target(tmp_path)

    binary = tmp_path / "image.bin"
    binary.write_bytes(b"\x00fixture")
    with pytest.raises(InputError, match="No supported text files could be scanned"):
        scan_target(binary)


def test_partial_archive_uses_the_same_coverage_contract(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    with ZipFile(archive, "w") as output:
        output.writestr("project/ok.sh", "echo fixture\n")
        output.writestr("project/broken.py", b"\x81invalid utf8")

    report = scan_target(archive)

    assert report.target.files_scanned == 1
    assert report.coverage.status == "partial"
    assert report.coverage.skipped_paths[0].path == "project/broken.py"


def test_configured_exclusions_are_outside_supported_file_coverage(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00fixture")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "broken.js").write_bytes(b"\x81fixture")

    report = scan_target(tmp_path)

    assert report.target.files_scanned == 1
    assert report.coverage.status == "complete"
    assert report.coverage.skipped_count == 0
    assert report.coverage.skipped_paths == ()


def test_skipped_path_details_are_bounded_but_count_remains_exact(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    for number in range(105):
        (tmp_path / f"bad-{number:03d}.py").write_bytes(b"\x81fixture")

    report = scan_target(tmp_path)

    assert report.coverage.status == "partial"
    assert report.coverage.skipped_count == 105
    assert len(report.coverage.skipped_paths) == 100


def test_unreadable_directory_is_reported_instead_of_silently_pruned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    denied = tmp_path / "private"
    denied.mkdir()

    def blocked_walk(root: Path, *, topdown: bool, followlinks: bool, onerror):
        yield str(root), ["private"], ["ok.py"]
        onerror(PermissionError(errno.EACCES, "fixture: access denied", str(denied)))

    monkeypatch.setattr(discovery.os, "walk", blocked_walk)

    report = scan_target(tmp_path)

    assert report.coverage.status == "partial"
    assert report.coverage.skipped_paths[0].path == "private"
    assert report.coverage.skipped_paths[0].reason.value == "unreadable"


def test_reparse_files_and_directories_are_recorded_without_reading_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "ok.py").write_text("# fixture\n", encoding="utf-8")
    (tmp_path / "linked.py").write_text("# must not be read\n", encoding="utf-8")
    (tmp_path / "linked-directory").mkdir()
    (tmp_path / "linked-directory" / "outside.py").write_text("# fixture\n", encoding="utf-8")
    original_open = Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path.name in {"linked.py", "outside.py"}:
            raise AssertionError("A linked path was read")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(
        discovery, "_is_link_or_reparse", lambda path: path.name.startswith("linked")
    )
    monkeypatch.setattr(Path, "open", guarded_open)

    report = scan_target(tmp_path)

    assert report.target.files_scanned == 1
    assert report.coverage.skipped_count == 2
    assert {item.path for item in report.coverage.skipped_paths} == {
        "linked.py",
        "linked-directory",
    }
    assert all(item.reason.value == "unsafe_path" for item in report.coverage.skipped_paths)


def test_no_sources_does_not_invoke_optional_ai(tmp_path: Path) -> None:
    class UnexpectedAI:
        def analyze(self, *args: object, **kwargs: object):
            raise AssertionError("No-source scan must stop before AI analysis")

    with pytest.raises(InputError, match="No supported text files could be scanned"):
        scan_target(tmp_path, ai=True, ai_analyzer=UnexpectedAI())
