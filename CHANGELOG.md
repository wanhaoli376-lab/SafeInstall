# Changelog

All notable changes to SafeInstall will be documented here. The project follows semantic
versioning after its first stable release.

## [Unreleased]

## [0.2.0a0] - 2026-08-12

### Added

- Experimental PySide6 desktop interface for local paths, supported archives, folders, and public
  GitHub repository URLs.
- Explicit drag-and-drop target preparation, worker-thread scans, bilingual overview/technical
  results, friendly redacted errors, optional AI settings, About page, and Markdown/JSON export.
- One-folder PyInstaller packaging with a locally validated Windows executable and a macOS app
  bundle configuration.
- Read-only, pinned GitHub Actions jobs for GUI regression tests and alpha desktop artifacts; the
  artifact workflow does not publish a GitHub Release.
- A bounded, commit-pinned GitHub HTTPS snapshot transport for portable systems without Git.

### Security

- Desktop scanning continues to use the existing static `scan_target()` boundary and never runs
  target code or installs dependencies.
- GUI startup and local scanning work without `OPENAI_API_KEY` or the optional OpenAI SDK.
- Report export rejects symlink destinations, avoids silent overwrite, writes new files with
  restricted permissions, and reuses centralized redaction.
- Untrusted desktop labels and evidence paths pass through centralized redaction; navigation is
  locked while the worker thread owns a scan.

## [0.1.0a0] - 2026-08-11

### Added

- Local-first CLI with terminal, JSON, and Markdown reports.
- Safe local, archive, and public GitHub repository loaders.
- Python, shell, PowerShell, batch, JavaScript, secret, dependency, workflow, supply-chain,
  prompt, Skill/plugin, and MCP scanning.
- Capability-aware risk engine and optional bounded OpenAI analysis.
- Rule/plugin extension foundations, security regressions, examples, and contributor guidance.
