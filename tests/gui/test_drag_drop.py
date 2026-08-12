import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6")

from PySide6.QtCore import QMimeData, QPointF, Qt, QUrl
from PySide6.QtGui import QDropEvent

from safeinstall.gui.i18n import Catalog
from safeinstall.gui.widgets import DropZone


def test_drop_zone_emits_one_local_target_without_scanning(
    tmp_path: Path,
    qtbot: object,
) -> None:
    target = tmp_path / "project"
    target.mkdir()
    zone = DropZone(Catalog("en"))
    qtbot.addWidget(zone)  # type: ignore[attr-defined]
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(target))])
    event = QDropEvent(
        QPointF(20, 20),
        Qt.DropAction.CopyAction,
        mime,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )

    with qtbot.waitSignal(zone.target_dropped, timeout=1_000) as signal:  # type: ignore[attr-defined]
        zone.dropEvent(event)

    assert signal.args == [str(target)]
    assert event.isAccepted()


def test_drop_zone_rejects_multiple_targets(tmp_path: Path) -> None:
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.touch()
    second.touch()
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(first)), QUrl.fromLocalFile(str(second))])

    assert DropZone.local_path_from_mime(mime) is None
