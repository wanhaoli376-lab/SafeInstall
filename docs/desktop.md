# Desktop and packaging

SafeInstall 0.2 alpha adds an experimental PySide6 desktop interface without changing the scan
core. The GUI calls `safeinstall.core.scan_target()` on a `QThread`; it never imports, executes,
builds, or installs target content.

## Run from source

```console
python -m pip install -e ".[gui]"
safeinstall-gui
```

The GUI extra does not install the OpenAI SDK. Local files, folders, and supported archives work
offline without an account or `OPENAI_API_KEY`. GitHub URL scans require network access, but use a
bounded HTTPS snapshot fallback when Git is not installed. AI explanation is a separate, explicit
opt-in and reads the key only from the process environment.

The first desktop release intentionally has no telemetry, persistent scan history, API-key store,
silent updater, installer, or automatic target execution. Markdown and JSON exports reuse the
core report renderers and their final redaction pass.

## Windows portable build

Build on 64-bit Windows with Python 3.11:

```console
python -m pip install -c constraints/release-python311.txt -e ".[gui,packaging]"
python -m PyInstaller --noconfirm --clean packaging/safeinstall.spec
dist\SafeInstall\SafeInstall.exe --smoke-test -platform offscreen
dist\SafeInstall\SafeInstall.exe --smoke-scan examples\safe-project -platform offscreen
```

The result is a one-folder build under `dist/SafeInstall/`. Distribute the complete folder inside
`SafeInstall-Windows-x64.zip`; the executable does not require a separate Python installation.
One-folder mode is deliberate: its collected dependencies are inspectable and it does not unpack
itself into a temporary directory on every launch.

The build spec includes the data-only built-in YAML rules and excludes the optional `openai`
package. A successful smoke test proves that the packaged Qt application can start and close; it
is not a malware-free certification of the build environment.

The public Alpha executable is currently unsigned. Windows SmartScreen may display a reputation
warning. Do not tell users to disable Defender or permanently disable SmartScreen. Authenticode
signing is future work and must not be claimed until a signed asset is independently verified.

Maintainers can also run the private packaging diagnostic
`SafeInstall.exe --smoke-scan <local-target> -platform offscreen`. It completes one real,
non-AI `scan_target()` call and reports success only when supported files were discovered. This
flag exists for build verification; it does not execute the target.

## macOS development build

PyInstaller must build separately on macOS; it is not a cross-compiler. On macOS the same spec
adds `dist/SafeInstall.app` with bundle identifier
`io.github.wanhaoli376-lab.safeinstall`.

The Alpha.2 release contract produces an **Apple Silicon (arm64) only** app and does not support
Intel Macs. The workflow uses GitHub's explicit `macos-15` arm64 runner, requires `uname -m` and
`lipo -archs` to report only `arm64`, prints the executable type with `file`, and runs the checked-in
bundle validator before packaging.

The PyInstaller spec reads the package version from `pyproject.toml`. For `0.2.0a2`, it writes
Apple-compatible `CFBundleShortVersionString=0.2.0`, `CFBundleVersion=2`, and the full
`SafeInstallPackageVersion=0.2.0a2`; the application About page continues to use the package's
full `__version__` value. Both the built app and final ZIP are rejected when these values are
empty, `0.0.0`, stale, or unrelated to the project version.

The macOS development artifact is **not signed with an Apple Developer ID and is not notarized**.
PyInstaller may apply ad-hoc signing required by the local toolchain, but users can still receive
a Gatekeeper warning. Do not describe the artifact as signed or notarized until a reviewed signing
workflow exists.

## GitHub Alpha Release

`.github/workflows/release.yml` runs only on manual dispatch or an alpha tag. It builds Windows
and macOS inputs with `contents: read`, pinned actions, reviewed release constraints, and no
product/API secrets. Manual dispatch is a build-only rehearsal. On a matching tag, one separate
publish job receives only `contents: write`.

Before publication the workflow requires the Windows and macOS builds, Windows folder/ZIP smoke
scans without `OPENAI_API_KEY`, the macOS smoke scan, a CycloneDX SBOM from a constrained Python
application dependency environment, and SHA-256 hashes over the two final ZIP files. The SBOM is
not a binary- or OS-component inventory. The workflow creates a private draft and verifies the
server-side files, then exposes the draft as a prerelease. The stable assets are:

- `SafeInstall-Windows-x64.zip`
- `SafeInstall-macOS-arm64-unsigned.zip`
- `SHA256SUMS.txt`
- `SBOM.json`

Both platform binaries remain unsigned. MSI/DMG installers, Windows Authenticode, Apple Developer
ID signing, notarization, and automatic updating are planned work. See
[Maintainer release process](maintainer-release.md).

## Planned binary boundary

The desktop target classifier rejects known unsupported `.exe`, `.msi`, `.dmg`, and `.pkg`
inputs. A future binary-analysis module may add PE, Mach-O, and ELF scanners behind the existing
finding/report boundary. No placeholder scanner currently claims that binaries were analyzed.
