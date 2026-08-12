# Security Policy

SafeInstall reads attacker-controlled repositories, archives, scripts, manifests, and prompts.
Security defects in its loaders, parsers, redaction, plugin boundary, or optional AI path can
therefore be high impact.

## Supported versions

Until the first stable release, only the latest commit on `main` is supported. Published
release support will be documented here when releases exist.

## Reporting a vulnerability

Please do not open a public issue, pull request, or discussion containing exploit details or a
real secret. Use GitHub's private vulnerability reporting feature after the repository is
published. If that feature is not yet available, contact the repository owner privately using
the address listed on their GitHub profile.

Include:

- the affected version or commit;
- the input type and smallest safe reproduction;
- the expected and observed behavior;
- likely impact and whether data left the scan boundary;
- any suggested mitigation.

Use placeholders for credentials and harmless fixtures for destructive behavior. Maintainers
should acknowledge a complete report within seven days, coordinate a fix and disclosure with
the reporter, and avoid promising a date before impact is understood.

## Security boundaries

SafeInstall promises that its default scan path does not execute or import target code. Archive
members remain inside a temporary extraction root, external repository values are passed to Git
as argument-vector data rather than shell text, and known credential formats are redacted before
reporting. Optional AI analysis and explicitly registered Python plugins are outside the trusted
static-analysis core and require an affirmative user choice.

These controls reduce risk but are not a claim that the software is vulnerability-free. See
[`docs/security-model.md`](docs/security-model.md) for threats, controls, and non-goals.
