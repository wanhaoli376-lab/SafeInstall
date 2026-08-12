"""Static PyInstaller entry point for the SafeInstall desktop application."""

from safeinstall.gui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
