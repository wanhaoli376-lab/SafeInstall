# Rule Development

Declarative rules let contributors add bounded pattern checks without changing scanner Python.
Built-in YAML lives in `src/safeinstall/rules/builtin/` so it is included in wheels. Use an AST or
structured scanner instead when correct detection requires syntax, aliases, nested context, or
data-flow reasoning.

## Rule schema

```yaml
- id: SI-SH-101
  name: Example network-to-shell pattern
  description: A fixture sends downloaded text to a shell.
  severity: high
  category: download_and_execute
  language: shell
  pattern: '\bcurl\b[^|#\n]*\|\s*(?:bash|sh)\b'
  explanation: Downloaded text can become code before a separate review step.
  recommendation: Download to a file, inspect it, and run only a trusted copy.
  capabilities:
    - network_access
    - download_execute
    - shell_execution
```

All fields are required except `capabilities`. Extra fields are rejected. IDs must use the
`SI-<AREA>-<NUMBER>` vocabulary and remain stable after release. Supported severity values are
`info`, `low`, `medium`, `high`, and `critical`; capability values are defined by
`safeinstall.models.Capability`.

## Choosing severity and wording

- `info`: relevant context with little direct impact.
- `low`: a common capability that needs context, such as a network request.
- `medium`: meaningful impact or a review-sensitive supply-chain choice.
- `high`: direct command execution, unsafe deserialization, destructive action, or automatic
  installation behavior.
- `critical`: a narrowly evidenced combination or strongly obfuscated direct execution, not a
  synonym for “looks suspicious.”

Describe what the pattern can do, not what its author intends. Explanations should make sense to
someone who does not know terms such as RCE or command injection. Recommendations must name the
next review action.

## Tests required

Every new rule needs:

1. a minimal positive fixture and expected file/line;
2. a nearby negative or benign-context fixture;
3. a redaction assertion if the match can contain a credential;
4. a risk expectation only when the rule changes risk semantics.

Fixtures must be inert strings, comments, or code that the test never runs. Do not add malware,
credential-stealing logic, or destructive payloads.

Run:

```console
python -m pytest tests/unit/test_rule_engine.py
python -m ruff check .
python -m ruff format --check .
```

Rule files are loaded as data with safe YAML, resource limits, a strict Pydantic schema, compiled
regular-expression validation, and duplicate-ID rejection. YAML tags cannot turn a rule into
executable Python. A rule that needs unbounded or pathological regular expressions will not be
accepted; prefer a purpose-built scanner.
