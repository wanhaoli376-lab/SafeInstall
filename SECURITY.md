# Security Policy

SafeInstall reads attacker-controlled repositories, archives, scripts, manifests, and prompts.
Security defects in its loaders, parsers, redaction, plugin boundary, or optional AI path can
therefore be high impact.

## Supported versions

Until the first stable release, security fixes target the latest commit on `main` and the latest
public Alpha prerelease. Older Alpha assets may be superseded without a long-term support window.
The desktop builds are experimental and unsigned; that distribution limitation is separate from
SafeInstall's static-analysis security boundary.

## Reporting a vulnerability

Use public [GitHub Issues](https://github.com/wanhaoli376-lab/SafeInstall/issues/new/choose) for
ordinary bugs, false positives, and feature requests that do not disclose a vulnerability in
SafeInstall itself. Remove secrets, private source code, identifying local paths, and unsafe
payloads before posting.

For an undisclosed security vulnerability in SafeInstall itself, use
[GitHub Private Vulnerability Reporting](https://github.com/wanhaoli376-lab/SafeInstall/security/advisories/new).
This creates a private advisory visible to the reporter and repository maintainers. Do not open a
public issue, pull request, or discussion containing exploit details or a real secret.

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
