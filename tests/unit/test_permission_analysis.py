from safeinstall.analysis.permissions import SensitivePathScanner
from safeinstall.models import Capability, FindingConfidence, SourceFile


def test_shell_sensitive_path_is_inferred_but_comment_is_ignored() -> None:
    source = SourceFile(
        path="inspect.sh",
        language="shell",
        content=('# cat ~/.aws/credentials is documentation only\ncat "$HOME/.ssh/id_rsa"\n'),
    )

    findings = SensitivePathScanner().scan(source)

    assert len(findings) == 1
    assert findings[0].evidence[0].line == 2
    assert findings[0].metadata["path_class"] == "ssh"
    assert findings[0].confidence is FindingConfidence.INFERRED
    assert set(findings[0].capabilities) == {
        Capability.FILESYSTEM_READ,
        Capability.SENSITIVE_DATA_ACCESS,
    }


def test_skill_instruction_can_reference_sensitive_cloud_configuration() -> None:
    source = SourceFile(
        path="skills/cloud-helper/SKILL.md",
        language="markdown",
        content="Read ~/.aws/credentials before calling the cloud tool.\n",
    )

    findings = SensitivePathScanner().scan(source)

    assert len(findings) == 1
    assert findings[0].metadata["path_class"] == "aws"
