# Project Analysis

## 1. Primary purpose and problem

SafeInstall helps people understand unfamiliar software, scripts, archives, and open-source
projects before running them. It statically identifies potential behavior, sensitive
capabilities, installation and supply-chain choices, and AI-extension instructions, then explains
the evidence in ordinary language. It is risk analysis, not antivirus software or a guarantee of
safety.

## 2. GitHub stars, forks, and contributors

**Available after public repository launch.** This project analysis does not invent repository
statistics. Once published, a future integration may retrieve public stars, forks, contributor
counts, default branch, and commit metadata from the GitHub API. Values unavailable without an
API call should be omitted rather than guessed.

## 3. Core functions and modules

- **Input Loader:** validates local paths, archives, and public GitHub URLs.
- **Static Scanner:** inspects Python, shell, PowerShell, batch, and JavaScript source as data.
- **Rules Engine:** loads strict community-contributed YAML patterns.
- **Behavior Analyzer:** describes filesystem, shell, network, environment, and combined behavior.
- **Dependency Scanner:** lists dependencies and reviews pins, Git sources, install hooks, and
  supported supply-chain configuration.
- **AI Component Scanner:** recognizes Skills, plugin manifests, prompts, and MCP components.
- **Risk Engine:** weighs severity, distinct capability/context, and explicit behavior chains.
- **Report Generator:** renders the same evidence as terminal, JSON, or Markdown.
- **Plugin System:** registers trusted scanner objects through an explicit registry.

## 4. Users

The intended audience includes ordinary computer users, students, GitHub users, developers, AI
agent users, MCP users, open-source maintainers, and security practitioners. A technical details
section preserves evidence for experts while the summary avoids requiring terms such as RCE,
SSRF, path traversal, or command injection.

## 5. Value to the open-source ecosystem

SafeInstall offers an open Scanner Plugin API and data-oriented rule model rather than keeping
all detection logic private. The community can review and improve language rules, supply-chain
rules, AI security rules, MCP capability rules, prompt-injection rules, explanations, and false-
positive fixtures. Stable IDs and evidence requirements make these contributions auditable.

## 6. Feature classification

| Area | v0.1 status |
|---|---|
| AI Agent analysis | Supported at a static prompt/component level; deeper semantics experimental |
| Plugin | Explicit trusted scanner framework implemented; distribution/store planned |
| Skill | `SKILL.md` identification, capability hints, and prompt-pattern review implemented |
| CLI | Implemented |
| Developer tools | JSON/Markdown output, rules, plugins, tests implemented |
| Automation | JSON output and GitHub CI implemented; hosted issue/PR automation planned |
| Code analysis | Implemented for supported text languages and manifests |
| Optional code-execution sandbox | Planned; no target execution exists in v0.1 |
| Third-party contributions | Governance and extension docs implemented; ecosystem grows after launch |
| MCP | Config/server/tool capability scanning implemented; protocol-wide semantic analysis planned |

## 7. SafeInstall's own security risks

The project must handle malicious code and scripts, prompt injection, API-key leakage,
unauthorized network requests, filesystem damage, archive traversal, supply-chain attacks,
third-party plugins/contributions, and malicious GitHub repositories. Parser denial of service,
Unicode/case path collisions, dependency compromise, false reassurance, and report injection are
additional concerns. Controls and residual risks are documented in `security-model.md`.

## 8. How Codex Security can help

Codex Security can assist reviewers with archive parser paths, traversal and Zip Slip, shell/
argument injection, secret leakage, plugin boundaries, AI prompt isolation, GitHub Actions,
supply-chain configuration, and third-party contribution attack paths. The useful output is a
reproducible source-to-sink trace and harmless regression test, not an unsupported vulnerability
label. See `codex-security.md` for the review checklist.

## 9. Practical OpenAI API quota use

Beyond opt-in product explanations, an authorized maintainer workflow may use API quota for issue
triage, duplicate suggestions, PR summaries, security PR review, release notes, changelogs,
documentation drafts, rule explanations, test generation, contributor support, and security-
finding explanations. False-positive analysis and candidate rule/test generation are especially
useful for a scanner, but every output requires human review and should receive only the minimum
repository data and permissions needed.
