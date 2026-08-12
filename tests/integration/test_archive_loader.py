from pathlib import Path
from zipfile import ZipFile

from safeinstall.loaders.archive import ArchiveLoader
from safeinstall.models import TargetKind


def test_safe_zip_is_available_only_inside_loader_context(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("project/main.py", "print('example')\n")

    with ArchiveLoader().open(archive) as target:
        extracted_root = target.root
        assert target.kind is TargetKind.ARCHIVE
        assert (target.root / "project" / "main.py").read_text(encoding="utf-8") == (
            "print('example')\n"
        )

    assert not extracted_root.exists()
