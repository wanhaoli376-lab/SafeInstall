from pathlib import Path

import yaml


def _template(name: str) -> dict[str, object]:
    path = Path(__file__).parents[2] / ".github" / "ISSUE_TEMPLATE" / name
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_alpha_feedback_template_requests_product_outcomes_and_privacy_check() -> None:
    document = _template("alpha_feedback.yml")
    body = document["body"]
    ids = {item.get("id") for item in body if isinstance(item, dict)}
    rendered = str(document)

    assert {"operating_system", "version", "target", "startup", "completion"} <= ids
    assert {"understandable", "false_positives", "privacy"} <= ids
    assert "confidential" in rendered
    assert "API keys" in rendered


def test_false_positive_template_requires_version_language_and_sanitized_example() -> None:
    document = _template("false_positive.yml")
    body = document["body"]
    ids = {item.get("id") for item in body if isinstance(item, dict)}
    rendered = str(document)

    assert {"version", "rule", "language", "evidence", "context"} <= ids
    assert "sanitized" in rendered
    assert "API keys" in rendered
