import pytest

pytest.importorskip("PySide6")

from safeinstall.exceptions import InputError, RepositoryLoadError, UnsafeArchiveError
from safeinstall.gui.error_presentation import present_error
from safeinstall.gui.i18n import Catalog


@pytest.mark.parametrize(
    ("error", "title_fragment", "message_fragment"),
    [
        (
            RepositoryLoadError("Git clone failed: unavailable"),
            "GitHub",
            "not exist",
        ),
        (UnsafeArchiveError("unsafe ZIP fixture"), "archive", "damaged"),
        (InputError("Target text files exceed the total scan size limit."), "large", "limit"),
    ],
)
def test_scan_errors_have_plain_language_and_bounded_technical_detail(
    error: Exception,
    title_fragment: str,
    message_fragment: str,
) -> None:
    result = present_error(error, Catalog("en"))

    assert title_fragment.lower() in result.title.lower()
    assert message_fragment.lower() in result.message.lower()
    assert len(result.technical_detail) <= 2_000
    assert "Traceback" not in result.technical_detail


def test_error_detail_is_redacted() -> None:
    secret = "".join(("sk-", "abcdefghijklmnopqrstuvwxyz123456"))

    result = present_error(ValueError(f"OPENAI_API_KEY={secret}"), Catalog("en"))

    assert secret not in result.technical_detail
    assert "sk-****...3456" in result.technical_detail
