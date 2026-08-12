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
python -m pip install -e ".[gui,packaging]"
python -m PyInstaller --noconfirm --clean packaging/safeinstall.spec
dist\SafeInstall\SafeInstall.exe --smoke-test -platform offscreen
```

The result is a one-folder build under `dist/SafeInstall/`. Distribute the complete folder inside
`SafeInstall-Windows-x64.zip`; the executable does not require a separate Python installation.
One-folder mode is deliberate: its collected dependencies are inspectable and it does not unpack
itself into a temporary directory on every launch.

The build spec includes the data-only built-in YAML rules and excludes the optional `openai`
package. A successful smoke test proves that the packaged Qt application can start and close; it
is not a malware-free certification of the build environment.

Maintainers can also run the private packaging diagnostic
`SafeInstall.exe --smoke-scan <local-target> -platform offscreen`. It completes one real,
non-AI `scan_target()` call and reports success only when supported files were discovered. This
flag exists for build verification; it does not execute the target.

## macOS development build

PyInstaller must build separately on macOS; it is not a cross-compiler. On macOS the same spec
adds `dist/SafeInstall.app` with bundle identifier
`io.github.wanhaoli376-lab.safeinstall`.

The current macOS development artifact is **not signed with an Apple Developer ID and is not
notarized**. PyInstaller may apply ad-hoc signing required by the local toolchain, but users can
still receive a Gatekeeper warning. Do not describe the artifact as signed or notarized until a
reviewed signing workflow exists.

## GitHub artifacts

`.github/workflows/release.yml` runs only on manual dispatch or an alpha tag. It builds Windows
and macOS artifacts with `contents: read`, pinned actions, no product/API secrets, and no Release
publishing step. Artifacts have short retention and are development outputs. Publishing a formal
GitHub Release, MSI/DMG installer, Developer ID signature, notarization, or automatic updater is
planned work and requires a separate security review.

## Planned binary boundary

The desktop target classifier rejects known unsupported `.exe`, `.msi`, `.dmg`, and `.pkg`
inputs. A future binary-analysis module may add PE, Mach-O, and ELF scanners behind the existing
finding/report boundary. No placeholder scanner currently claims that binaries were analyzed.
