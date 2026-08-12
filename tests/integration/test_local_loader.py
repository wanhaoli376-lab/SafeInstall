from pathlib import Path

import pytest

from safeinstall.exceptions import InputError
from safeinstall.loaders.discovery import DiscoveryLimits, FileDiscoverer
from safeinstall.loaders.local import LocalLoader


def test_local_directory_discovers_source_without_dependency_or_binary_trees(
    tmp_path: Path,
) -> None:
    project = tmp_path / "示例-project"
    project.mkdir()
    (project / "app.py").write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")
    (project / "README.md").write_text("# Example\n", encoding="utf-8")
    (project / "image.bin").write_bytes(b"\x00\x01\x02")
    (project / "node_modules").mkdir()
    (project / "node_modules" / "vendor.js").write_text("eval('ignored')\n", encoding="utf-8")
    (project / ".git").mkdir()
    (project / ".git" / "config").write_text("token=ignored\n", encoding="utf-8")

    with LocalLoader().open(project) as target:
        sources = FileDiscoverer().discover(target)

    assert [source.path for source in sources] == ["README.md", "app.py"]
    assert sources[1].language == "python"


def test_single_file_target_does_not_scan_sibling_files(tmp_path: Path) -> None:
    selected = tmp_path / "selected.sh"
    selected.write_text("echo safe\n", encoding="utf-8")
    (tmp_path / "unrelated.py").write_text("import os\nos.system('ignored')\n", encoding="utf-8")

    with LocalLoader().open(selected) as target:
        sources = FileDiscoverer().discover(target)

    assert [source.path for source in sources] == ["selected.sh"]
    assert sources[0].language == "shell"


def test_discovery_bounds_all_directory_entries_not_only_supported_files(
    tmp_path: Path,
) -> None:
    project = tmp_path / "many-files"
    project.mkdir()
    for number in range(3):
        (project / f"unsupported-{number}.bin").write_bytes(b"fixture")

    discoverer = FileDiscoverer(limits=DiscoveryLimits(max_entries=2))

    with (
        LocalLoader().open(project) as target,
        pytest.raises(InputError, match="directory entries"),
    ):
        discoverer.discover(target)
