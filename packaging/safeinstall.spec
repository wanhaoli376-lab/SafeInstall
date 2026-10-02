# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller one-folder build for the experimental desktop application."""

from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files

project_root = Path(SPEC).resolve().parent.parent
source_root = project_root / "src"
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from tools.release import macos_bundle_versions, validate_project_version

package_version = validate_project_version(project_root)
bundle_short_version, bundle_build_version = macos_bundle_versions(package_version)
rule_data = collect_data_files(
    "safeinstall.rules.builtin",
    includes=["*.yml"],
)

analysis = Analysis(
    [str(project_root / "packaging" / "desktop_entry.py")],
    pathex=[str(source_root)],
    binaries=[],
    datas=rule_data,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["openai"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="SafeInstall",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
portable = COLLECT(
    executable,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SafeInstall",
)

if sys.platform == "darwin":
    macos_app = BUNDLE(
        portable,
        name="SafeInstall.app",
        icon=None,
        bundle_identifier="io.github.wanhaoli376-lab.safeinstall",
        info_plist={
            "CFBundleShortVersionString": bundle_short_version,
            "CFBundleVersion": bundle_build_version,
            "SafeInstallPackageVersion": package_version,
            "NSHighResolutionCapable": True,
        },
    )
