import pytest

from safeinstall.core import _extend_bounded
from safeinstall.exceptions import InputError


def test_repository_wide_result_collection_is_bounded() -> None:
    collected: list[int] = []

    with pytest.raises(InputError, match="configured limit"):
        _extend_bounded(collected, range(3), limit=2, label="findings")

    assert collected == [0, 1]
