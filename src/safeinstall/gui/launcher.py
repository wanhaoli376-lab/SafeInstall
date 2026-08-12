"""Dependency-light entry point for the optional desktop interface."""

from __future__ import annotations

import importlib
import sys
from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Start the GUI or return a concise optional-dependency error."""

    try:
        module = importlib.import_module("safeinstall.gui.app")
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("PySide6"):
            print(
                "SafeInstall GUI is not installed. Install the optional dependency with "
                "pip install 'safeinstall[gui]'.",
                file=sys.stderr,
            )
            return 2
        raise
    return int(module.main(argv))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
