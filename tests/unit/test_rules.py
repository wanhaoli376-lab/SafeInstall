from pathlib import Path

import pytest

from safeinstall.exceptions import RuleLoadError
from safeinstall.models import Capability, Severity
from safeinstall.rules.loader import load_rule_file, load_rule_text
from safeinstall.rules.registry import RuleRegistry


def test_yaml_rule_is_validated_and_registered_by_language(tmp_path: Path) -> None:
    rule_path = tmp_path / "unsafe-shell.yml"
    rule_path.write_text(
        """
id: SI-PY-001
name: Unsafe shell execution
description: Detects subprocess calls that explicitly enable a shell.
severity: high
category: command_execution
language: python
pattern: 'shell\\s*=\\s*True'
explanation: This code asks the operating system shell to interpret a command.
recommendation: Check whether untrusted input can reach the command.
capabilities:
  - shell_execution
""".strip(),
        encoding="utf-8",
    )

    rule = load_rule_file(rule_path)[0]
    registry = RuleRegistry([rule])

    assert rule.severity is Severity.HIGH
    assert rule.capabilities == (Capability.SHELL_EXECUTION,)
    assert registry.for_language("python") == (rule,)


def test_registry_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    rule_path = tmp_path / "duplicate.yml"
    rule_path.write_text(
        """
- id: SI-PY-001
  name: First rule
  description: First definition.
  severity: low
  category: code_execution
  language: python
  pattern: eval
  explanation: Dynamic evaluation was observed.
  recommendation: Review the evaluated input.
- id: SI-PY-001
  name: Second rule
  description: Conflicting definition.
  severity: high
  category: code_execution
  language: python
  pattern: exec
  explanation: Dynamic execution was observed.
  recommendation: Review the executed input.
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="Duplicate rule id"):
        RuleRegistry(load_rule_file(rule_path))


def test_rule_loader_rejects_python_object_yaml_tags(tmp_path: Path) -> None:
    rule_path = tmp_path / "object-tag.yml"
    rule_path.write_text(
        "!!python/object/apply:builtins.print ['rule content must remain data']",
        encoding="utf-8",
    )

    with pytest.raises(RuleLoadError, match="Could not load rule file"):
        load_rule_file(rule_path)


def test_rule_loader_rejects_excessive_yaml_aliases() -> None:
    aliases = "\n".join("  - *shared" for _ in range(51))
    rule_text = f"shared: &shared value\naliases:\n{aliases}\n"

    with pytest.raises(RuleLoadError, match="alias limit"):
        load_rule_text(rule_text, source="alias-fixture.yml")
