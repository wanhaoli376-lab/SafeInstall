# OpenAI API: Product and Maintenance Use

OpenAI is an optional enhancement, never a requirement for SafeInstall's local static scan. The
current client uses the Responses API, fixed high-priority instructions, bounded user-data input,
`store=False`, and strict JSON validation. OpenAI recommends the Responses API for new projects;
maintainers should re-check the [official migration guide](https://developers.openai.com/api/docs/guides/migrate-to-responses)
and [current model guidance](https://developers.openai.com/api/docs/guides/latest-model) before
changing the default model or request shape.

## In-product use

Only `safeinstall scan TARGET --ai` makes an AI request. Local scanners run first. SafeInstall
sends at most 20 redacted findings and three prompt files of at most 4,000 characters each. The
model may explain findings, rank review priorities, discuss possible behavior chains, flag prompt
injection context, and summarize inferred capabilities. It must not declare a target safe or
malicious, execute a tool, or change local risk.

`OPENAI_API_KEY` is read only from the process environment. It must not appear in source, sample
configuration, test fixtures, logs, reports, or repository secrets exposed to pull-request jobs.
Code that cannot leave an environment must be scanned without `--ai`.

## Maintainer workflows

Separate, explicitly authorized automation may use API quota for:

- issue triage into bug, false positive, feature, rule request, scanner, documentation, or security;
- possible duplicate-issue suggestions;
- false-positive analysis and candidate rule refinements;
- pull-request summaries and identification of security-sensitive modules;
- security pull-request review and source-to-sink questions;
- release notes and changelog drafts;
- documentation and plain-language rule explanations;
- candidate tests and inert fixtures;
- contributor support and first-pass issue clarification.

These workflows are planned maintenance aids, not part of the v0.1 CLI. They require an approved
repository integration, minimal token permissions, input/output retention decisions, cost limits,
and a human owner. A model-generated rule, test, release note, or security conclusion is never
merged or published without human review.

## Maintenance checklist

Before changing SDK or model configuration:

1. verify current SDK/Responses documentation from an official OpenAI domain;
2. run prompt-injection, redaction, no-key, malformed-output, timeout, and size-limit tests;
3. inspect the exact serialized payload and confirm target data is not in `instructions`;
4. confirm no tools, target repository access, or environment values are provided;
5. document cost/latency and any change in data sent to the API;
6. preserve a fully functional no-key, no-network static scan.
