# Changelog

All notable changes to SafeInstall will be documented here. The project follows semantic
versioning after its first stable release.

## [Unreleased]

### Preparing 0.2.0a2

- Added a working private vulnerability-reporting route and clarified that ordinary bugs,
  false positives, and feature requests remain public Issues.
- Renamed the future macOS asset to `SafeInstall-macOS-arm64-unsigned.zip` and documented that
  it supports Apple Silicon only, not Intel Macs.
- Derived Apple bundle marketing/build versions from `pyproject.toml` and added Info.plist plus
  arm64 Mach-O release validation.
- Pinned the future macOS job to GitHub's `macos-15` arm64 runner and added `uname`, `file`, and
  `lipo` build gates.
- Added release-documentation and Issue Form label contract checks.

This is a development version. No `v0.2.0-alpha.2` Tag or Release has been created.

## [0.2.0a1] - 2026-08-12

### Added

- First public desktop Alpha Release with stable Windows x64 and unsigned macOS asset names.
- SHA-256 checksums for the final ZIP assets and a CycloneDX constrained Python-dependency SBOM.
- Public Alpha testing guide, maintainer release checklist, real GUI screenshots, and sanitized
  Alpha/false-positive feedback forms.

### Changed

- Release builds now use reviewed Python 3.11 constraints instead of resolving critical desktop
  and packaging dependencies from floating ranges.
- The release workflow separates read-only Windows/macOS builds and metadata verification from
  the only job allowed to create a GitHub prerelease.
- Windows packaging now performs real local folder and ZIP smoke scans without an API key,
  including paths with spaces and non-ASCII characters.

### Security

- Publication uses a private draft, verifies the exact four server-side assets and their hashes,
  and only then exposes the Release as a prerelease.
- Release workflow triggers, action pins, permissions, AI-key absence, unsigned artifact naming,
  checksums, and SBOM requirements are covered by regression tests.
- Portable builds continue to exclude the OpenAI SDK and do not execute scanned targets.

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
