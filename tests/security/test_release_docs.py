from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_security_policy_routes_public_feedback_and_private_vulnerabilities() -> None:
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "https://github.com/wanhaoli376-lab/SafeInstall/security/advisories/new" in policy
    assert "https://github.com/wanhaoli376-lab/SafeInstall/issues/new/choose" in policy
    assert "bugs, false positives, and feature requests" in policy
    assert "GitHub profile" not in policy
    assert "profile email" not in policy.casefold()


def test_current_alpha1_macos_limitations_are_consistent_in_public_docs() -> None:
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    chinese = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")
    release = (ROOT / "docs" / "releases" / "v0.2.0-alpha.1.md").read_text(encoding="utf-8")

    for document in (english, release):
        assert "SafeInstall-macOS-unsigned.zip" in document
        assert "Apple Silicon (arm64)" in document
        assert "does not support Intel Macs" in document
        assert "Apple Developer ID" in document
        assert "not notarized" in document
        assert "Gatekeeper" in document

    assert "SafeInstall-macOS-unsigned.zip" in chinese
    assert "Apple Silicon" in chinese and "arm64" in chinese
    assert "不支持 Intel Mac" in chinese
    assert "Apple Developer ID" in chinese
    assert "notarize" in chinese
    assert "Gatekeeper" in chinese


def test_readmes_distinguish_public_alpha1_from_alpha2_in_preparation() -> None:
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    chinese = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

    assert "Current public release: v0.2.0-alpha.1" in english
    assert "preparing 0.2.0a2" in english
    assert "当前公开版本：v0.2.0-alpha.1" in chinese
    assert "正在准备 0.2.0a2" in chinese
    for document in (english, chinese):
        assert "SafeInstall-macOS-arm64-unsigned.zip" in document
        assert "releases/tag/v0.2.0-alpha.2" not in document


def test_alpha2_release_notes_define_the_new_arm64_asset_without_claiming_release() -> None:
    notes = (ROOT / "docs" / "releases" / "v0.2.0-alpha.2.md").read_text(encoding="utf-8")

    assert "SafeInstall v0.2.0-alpha.2" in notes
    assert "SafeInstall-macOS-arm64-unsigned.zip" in notes
    assert "SafeInstall-macOS-unsigned.zip" not in notes
    assert "Apple Silicon (arm64)" in notes
    assert "does not support Intel Macs" in notes
    assert "not signed with an Apple Developer ID" in notes
    assert "not notarized" in notes


def test_future_release_contract_uses_the_explicit_arm64_asset_name() -> None:
    paths = (
        ROOT / ".github" / "workflows" / "release.yml",
        ROOT / "tools" / "release.py",
        ROOT / "docs" / "desktop.md",
        ROOT / "docs" / "maintainer-release.md",
    )
    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert "SafeInstall-macOS-arm64-unsigned.zip" in content
        assert "SafeInstall-macOS-unsigned.zip" not in content

    maintainer = (ROOT / "docs" / "maintainer-release.md").read_text(encoding="utf-8")
    assert "0.2.0a2" in maintainer
    assert "v0.2.0-alpha.2" in maintainer
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "Preparing 0.2.0a2" in changelog
