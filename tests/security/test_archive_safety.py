import stat
import tarfile
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

import pytest

from safeinstall.exceptions import UnsafeArchiveError
from safeinstall.loaders.archive import ArchiveLoader


def test_zip_slip_member_cannot_escape_temporary_workspace(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.zip"
    temp_parent = tmp_path / "work"
    temp_parent.mkdir()
    outside = tmp_path / "outside.txt"
    with ZipFile(archive, "w", compression=ZIP_DEFLATED) as zip_file:
        zip_file.writestr("../../outside.txt", "must not be written")

    loader = ArchiveLoader(temp_parent=temp_parent)

    with pytest.raises(UnsafeArchiveError, match="unsafe path"), loader.open(archive):
        pytest.fail("an unsafe archive must not produce a loaded target")

    assert not outside.exists()


def test_zip_symlink_member_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.zip"
    link = ZipInfo("link-to-outside")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr(link, "../../outside.txt")

    with (
        pytest.raises(UnsafeArchiveError, match="links are not allowed"),
        ArchiveLoader().open(archive),
    ):
        pytest.fail("an archive link must not be extracted")


def test_tar_traversal_member_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.tar.gz"
    payload = b"must not be written"
    member = tarfile.TarInfo("../../outside.txt")
    member.size = len(payload)
    with tarfile.open(archive, "w:gz") as tar_file:
        tar_file.addfile(member, BytesIO(payload))

    with pytest.raises(UnsafeArchiveError, match="unsafe path"), ArchiveLoader().open(archive):
        pytest.fail("an unsafe TAR archive must not be loaded")


def test_tar_symlink_to_outside_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "symlink.tar"
    member = tarfile.TarInfo("link-to-outside")
    member.type = tarfile.SYMTYPE
    member.linkname = "../../outside.txt"
    with tarfile.open(archive, "w") as tar_file:
        tar_file.addfile(member)

    with (
        pytest.raises(UnsafeArchiveError, match="links are not allowed"),
        ArchiveLoader().open(archive),
    ):
        pytest.fail("a TAR link must not be extracted")


def test_overlong_archive_filename_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "long-name.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("a" * 5000 + ".txt", "example")

    with pytest.raises(UnsafeArchiveError, match="unsafe path"), ArchiveLoader().open(archive):
        pytest.fail("an overlong member name must not be extracted")


def test_unicode_archive_filename_stays_inside_workspace(tmp_path: Path) -> None:
    archive = tmp_path / "unicode.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("项目/安全.py", "value = 1\n")

    with ArchiveLoader().open(archive) as target:
        extracted = target.root / "项目" / "安全.py"
        assert extracted.is_file()
        assert extracted.resolve().is_relative_to(target.root.resolve())


@pytest.mark.parametrize("member_name", ["safe.txt:payload", "CON.txt", "trailing-dot."])
def test_windows_ambiguous_archive_names_are_rejected(tmp_path: Path, member_name: str) -> None:
    archive = tmp_path / "ambiguous-name.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr(member_name, "fixture")

    with pytest.raises(UnsafeArchiveError, match="unsafe path"), ArchiveLoader().open(archive):
        pytest.fail("an ambiguous Windows path must not be extracted")


def test_unicode_equivalent_archive_names_are_rejected_as_duplicates(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "unicode-collision.zip"
    with ZipFile(archive, "w") as zip_file:
        zip_file.writestr("caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "first")
        zip_file.writestr("cafe\N{COMBINING ACUTE ACCENT}.txt", "second")

    with pytest.raises(UnsafeArchiveError, match="duplicate path"), ArchiveLoader().open(archive):
        pytest.fail("canonically equivalent paths must not be extracted twice")
