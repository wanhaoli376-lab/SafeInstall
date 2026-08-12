# Contributing to SafeInstall

Thank you for helping people understand unfamiliar software before they run it. Contributions
may add a scanner, declarative rule, test, documentation, AI security check, MCP rule, or a
carefully scoped core improvement.

## Before you start

Search existing issues first. For a behavior change, describe the target format, evidence that
can be observed statically, likely false positives, and the plain-language explanation a user
needs. Never submit a real credential, destructive payload, or live malicious sample.

Small rule and documentation changes can go directly to a pull request. Discuss a new loader,
plugin execution path, network behavior, or public API before investing in a large change.

## Local setup

```console
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

For desktop changes, install the optional GUI test stack and keep Qt offscreen in automation:

```console
python -m pip install -e ".[dev,gui,gui-test]"
python -m pytest tests/gui
```

Add focused tests before or with an implementation. Every finding should include a stable rule
ID, severity, category, explanation, recommendation, and exact file/line evidence. Describe a
capability or potential risk; do not label a target malicious without proof.

## Contribution types

- **Rules:** add valid YAML and positive/negative fixtures; explain expected context.
- **Scanners:** parse target content as data and enforce resource limits.
- **Plugins:** keep registration explicit and document the trust boundary.
- **AI/Prompt/MCP:** treat every target string as untrusted data and test instruction isolation.
- **Documentation:** keep supported, experimental, and planned behavior distinct.
- **Tests:** use inert strings, mocks, and temporary directories only.

See [`docs/rule-development.md`](docs/rule-development.md) and
[`docs/plugin-development.md`](docs/plugin-development.md) for the extension contracts.

## Security-sensitive review

Changes under `loaders/`, `plugins/`, `analysis/ai_analysis.py`, `gui/workers.py`, GUI export or
packaging code, archive parsing, redaction, or `.github/workflows/` require explicit security
review. Reviewers should check path containment, links/reparse points, subprocess argument
boundaries, thread lifecycle, export overwrite/symlink behavior, time/size limits, secret
handling, prompt isolation, and behavior on an untrusted pull request.

Workflow tests for outside contributions must not receive `OPENAI_API_KEY`, elevated
`GITHUB_TOKEN` permissions, deployment credentials, or other repository secrets.

Release dependency pins live in `constraints/release-python311.txt`; development ranges remain in
`pyproject.toml`. Any change to release pins, PyInstaller inputs, SBOM generation, checksums, asset
names, or publication permissions requires a build-only workflow rehearsal and review against
[`docs/maintainer-release.md`](docs/maintainer-release.md).

## Pull requests

Keep each pull request focused. Complete the template, include tests, document user-visible
changes, and state which untrusted-input boundary was considered. All automated checks and
human review must pass. Generated rules and tests require the same review as hand-written code.

By contributing, you agree that your contribution is licensed under the MIT License and that
you will follow the Code of Conduct.
