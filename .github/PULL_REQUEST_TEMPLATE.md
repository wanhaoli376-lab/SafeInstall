## Purpose

<!-- What user or maintainer problem does this change solve? -->

## Changes

<!-- Summarize the code, rule, test, and documentation changes. -->

## Evidence

- [ ] Tests cover the intended match or behavior.
- [ ] Nearby benign/negative context is covered where relevant.
- [ ] `python -m pytest` passes.
- [ ] `python -m ruff check .` and `python -m ruff format --check .` pass.

## Security review

- [ ] Target content remains untrusted data and is never executed or imported.
- [ ] Paths, links, subprocess arguments, parser limits, and temporary files were considered.
- [ ] Reports, errors, fixtures, and optional API payloads do not expose real secrets.
- [ ] No pull-request workflow receives an API key or elevated token.
- [ ] Findings distinguish observed facts, bounded inference, and recommendations.

Security-sensitive area changed (loader, plugin, AI, redaction, workflow): **yes / no**

<!-- If yes, describe the source-to-sink path and the reviewer focus. -->
