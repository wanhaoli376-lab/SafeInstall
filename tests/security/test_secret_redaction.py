import io
import logging

from safeinstall.logging import RedactingFormatter
from safeinstall.models import SourceFile
from safeinstall.redaction import redact_data, redact_text
from safeinstall.scanners.secrets import SecretScanner

_OPENAI_KEY_FIXTURE = "".join(("sk-", "abcdefghijklmnopqrstuvwxyz123456"))


def test_secret_finding_never_contains_the_complete_secret() -> None:
    openai_key = _OPENAI_KEY_FIXTURE
    password = "correct-horse-battery-staple"
    source = SourceFile(
        path="config.py",
        language="python",
        content=(f'OPENAI_API_KEY = "{openai_key}"\npassword = "{password}"\n'),
    )

    findings = SecretScanner().scan(source)
    serialized = "\n".join(finding.model_dump_json() for finding in findings)

    assert len(findings) == 2
    assert openai_key not in serialized
    assert password not in serialized
    assert "sk-****...3456" in serialized


def test_short_environment_secret_is_redacted_too() -> None:
    source = SourceFile(
        path=".env",
        language="text",
        content="OPENAI_API_KEY=example\n",
    )

    findings = SecretScanner().scan(source)
    serialized = "\n".join(finding.model_dump_json() for finding in findings)

    assert "example" not in serialized
    assert "OPENAI_API_KEY=****" in serialized


def test_log_formatter_redacts_values_after_message_interpolation() -> None:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger = logging.getLogger("safeinstall.test.redaction")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)

    logger.info("OPENAI_API_KEY=%s", _OPENAI_KEY_FIXTURE)

    output = stream.getvalue()
    assert _OPENAI_KEY_FIXTURE not in output
    assert "sk-****...3456" in output


def test_dotenv_file_is_reported_without_exposing_its_contents() -> None:
    source = SourceFile(
        path="config/.env",
        language="text",
        content="# values intentionally omitted from this fixture\n",
    )

    findings = SecretScanner().scan(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SI-SEC-007"
    assert findings[0].evidence[0].snippet is None


def test_quoted_password_with_spaces_is_fully_redacted() -> None:
    password = "correct horse battery staple"  # noqa: S105 - inert redaction fixture
    source = SourceFile(
        path="settings.py",
        language="python",
        content=f'secret_sauce = "{password}"\n',
    )

    findings = SecretScanner().scan(source)
    serialized = "\n".join(finding.model_dump_json() for finding in findings)

    assert password not in serialized
    assert findings[0].evidence[0].snippet == 'secret_sauce = "co****...aple"'


def test_private_key_body_and_sensitive_mapping_keys_are_redacted() -> None:
    private_body = "cHJpdmF0ZS1rZXktZml4dHVyZQ=="  # noqa: S105 - inert fixture
    private_key = f"-----BEGIN PRIVATE KEY-----\n{private_body}\n-----END PRIVATE KEY-----"
    sensitive_key = "token=abcdefghijklmnopqrstuvwxyz"  # noqa: S105 - inert fixture

    assert private_body not in redact_text(private_key)
    redacted = redact_data({sensitive_key: "safe"})
    assert sensitive_key not in redacted


def test_secret_findings_are_bounded_per_file() -> None:
    source = SourceFile(
        path="generated.env",
        language="text",
        content="password=fixture-value\n" * 1_001,
    )

    findings = SecretScanner().scan(source)

    assert len(findings) == 1_000


def test_terminal_and_bidi_control_characters_are_made_visible() -> None:
    untrusted_name = "report\x1b[31m\N{RIGHT-TO-LEFT OVERRIDE}.py"

    redacted = redact_text(untrusted_name)

    assert "\x1b" not in redacted
    assert "\N{RIGHT-TO-LEFT OVERRIDE}" not in redacted
    assert redacted == "report\\u001b[31m\\u202e.py"
