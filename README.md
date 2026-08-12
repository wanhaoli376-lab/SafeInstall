# SafeInstall

[English](README.md) | [简体中文](README.zh-CN.md)

> **Understand software before you run it.**

SafeInstall analyzes unknown scripts, open-source projects, AI plugins, Skills, and MCP
servers before you run them. It turns security-relevant code patterns into a report that
explains what a target may be able to do, where the evidence is, and what to review next.

SafeInstall is local-first and static by default. It never installs dependencies, imports a
target package, or executes scanned code. Optional OpenAI analysis is off unless you pass
`--ai`.

> [!IMPORTANT]
> SafeInstall provides risk analysis, not a malware-free guarantee. It does not replace
> antivirus software, sandboxing, code review, or trust in the software source.

## Why SafeInstall

Commands such as `curl example.com/install.sh | bash` are compact but hide an important
fact: network content is downloaded and immediately interpreted by a shell. Likewise,
`subprocess.run(...)`, an npm `postinstall` hook, or an MCP filesystem tool may be legitimate
while still giving software meaningful control over a computer.

SafeInstall separates three things that security reports often blur together:

- **Facts:** the exact pattern, file, and line that were observed.
- **Inference:** a bounded capability or behavior-chain assessment.
- **Advice:** a practical next review step, without claiming the project is malicious.

## Features

- Local files and folders, ZIP/TAR archives, and public GitHub repositories
- Python, shell, PowerShell, batch, and JavaScript/Node.js static scanners
- Dependency, install-script, Dockerfile, and GitHub Actions supply-chain checks
- Secret detection with centralized redaction; reports never intentionally print full values
- Skill, plugin manifest, MCP server, tool-definition, and prompt-injection checks
- Capability summaries for files, shell, network, environment, Git, privilege, and persistence
- Context-aware risk scoring, including environment-read plus unknown outbound POST behavior
- Human-readable terminal output plus stable JSON and GitHub-ready Markdown
- Strict YAML rule loading and an explicit scanner plugin registry
- Bounded, opt-in OpenAI explanations that receive only redacted findings and prompt excerpts

## Installation

SafeInstall has not been published to PyPI yet. Install it from a trusted clone:

```console
git clone https://github.com/wanhaoli376-lab/SafeInstall.git
cd SafeInstall
python -m pip install -e .
```

For development:

```console
python -m pip install -e ".[dev]"
```

Optional AI support is a separate extra:

```console
python -m pip install -e ".[ai]"
```

## Quick Start

```console
safeinstall --help
safeinstall scan ./unknown-project
safeinstall scan ./download.zip
safeinstall scan https://github.com/OWNER/REPOSITORY
safeinstall scan ./unknown-project --format json
safeinstall scan ./unknown-project --format markdown
```

Nothing in the target is run by these commands. Public GitHub repositories are shallow-cloned
to a restricted temporary directory with hooks and Git LFS smudging disabled, scanned, then
removed.

### Example report

```text
SafeInstall Report
Target: example/project
Overall Risk: HIGH

What this software may do:
[!] Run commands on your computer
[!] Read environment variables
[!] Send outbound network requests

Primary reasons:
1. Environment data is read and can be sent to an unknown destination.
2. A subprocess call enables shell interpretation at installer.py:18.

Recommendation:
Review the installation path and network destination before running this project.

Static analysis only. These findings do not prove malicious intent.
```

Try the bundled fixtures:

```console
safeinstall scan ./examples/safe-project
safeinstall scan ./examples/risky-project
```

The risky example is inert: it contains unreachable fixture code, comments, and test strings
rather than a destructive command or working payload.

## Supported Targets

| Status | Targets and analysis |
|---|---|
| Supported | Local file/folder, ZIP, TAR/TAR.GZ, public GitHub repository |
| Supported | Python, shell, PowerShell, batch, JavaScript/Node.js |
| Supported | Python/npm manifests, lockfiles, install scripts, Dockerfiles, GitHub Actions |
| Supported | Skills, plugin manifests, MCP configurations/servers, prompt-like Markdown |
| Experimental | External YAML rules, trusted in-process scanner plugins, optional AI summaries |
| Planned | Deep binary formats (`.exe`, `.msi`, `.dmg`, `.pkg`), Go, Rust, APK, Office macros |
| Planned | Isolated execution sandbox and graphical interface; neither exists in v0.1 |

Unsupported or unrecognized content may be skipped. A clean report means that no supported
pattern was found; it does not prove safety.

## Optional AI Analysis

```console
safeinstall scan ./project --ai
```

AI mode reads `OPENAI_API_KEY` only from the process environment. The key is never placed in a
sample configuration or report. SafeInstall scans locally first, selects a bounded number of
findings and prompt files, redacts recognized secrets, and then sends those excerpts to the
OpenAI API. Target content is placed in the user-data portion of a fixed prompt and is always
treated as untrusted data.

Do not use `--ai` if code is not permitted to leave your environment. AI output is explanatory
and cannot lower the locally calculated risk or act as a security boundary. See
[OpenAI API maintenance](docs/openai-api-maintenance.md) and the
[security model](docs/security-model.md).

## Rules and Plugins

Declarative rules use a strict schema with an ID, name, description, severity, category,
language, pattern, explanation, recommendation, and capabilities. Invalid fields, duplicate
IDs, unsafe YAML tags, or oversized rule files are rejected. See
[Rule development](docs/rule-development.md).

Scanner plugins are trusted Python code and must be registered explicitly; simply placing code
inside a scanned repository never loads it. There is no online plugin store. See
[Plugin development](docs/plugin-development.md).

## Development

```console
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

The security suite covers archive traversal, symlink escape, secret redaction, malicious
filenames, Git URL injection, and AI prompt isolation.

## Roadmap

- **v0.1 alpha:** CLI, safe loaders, core language scanners, secrets, reports, and examples
- **v0.2:** deeper Node.js/PowerShell context, lockfile coverage, and GitHub Actions analysis
- **v0.3:** richer Skill/plugin/MCP semantics and opt-in AI behavior-chain review
- **v0.4:** documented plugin SDK and broader community rule packs
- **v1.0:** stable rule/plugin APIs and supported CI integration

The v0.1 codebase already includes early implementations of several later items; those APIs
remain experimental until their milestone is complete.

## Contributing and Security

Contributions are welcome for scanners, rules, tests, documentation, AI security checks, and
MCP analysis. Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing security-sensitive
loaders, plugin execution, AI integration, or workflows.

Do not open a public issue for a vulnerability in SafeInstall. Follow
[SECURITY.md](SECURITY.md) instead. By participating, you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

Licensed under the [MIT License](LICENSE).
