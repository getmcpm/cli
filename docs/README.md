# Documentation by task

## Use mcpm

- [Quick start](../README.md#quick-start) and [installation channels](DISTRIBUTION.md).
- [CLI workflows, stacks and command index](USAGE.md).
- [Trust scores, scanner protocol and supply-chain evidence](TRUST.md).
- [Guard setup, remediation and confinement](GUARD.md).
- [Project scope inventory](PROJECT-SCOPE.md) and [local artifact comparison](ARTIFACT-REVIEW.md).
- [Agent evidence/workflows](AGENT-WORKFLOW.md) and the self-contained
  [public usage skill](../skills/mcpm/SKILL.md).

## Understand security and contracts

- [Guard carrier coverage](GUARD.md#protocol-and-carrier-coverage),
  [policy](POLICY.md), [signatures](SIGNATURES.md) and [OWASP mapping](owasp-mcp-mapping.md).
- [Runtime relay, confinement and agent hooks](GUARD.md#runtime-relay-confinement-and-agent-hooks).
- [CLI/JSON/lock contracts](CONTRACTS.md), [architecture](ARCHITECTURE.md)
  and [private security reporting](../SECURITY.md).

## Contribute and release

- [CONTRIBUTING](../CONTRIBUTING.md), [shared agent instructions](../AGENTS.md)
  and [maintainer workflow/current checkpoint](MAINTAINER-WORKFLOW.md).
- Repo-owned [development](../.agents/skills/mcpm-development/SKILL.md) and
  [release](../.agents/skills/mcpm-release/SKILL.md) skills.
- [Selected active backlog](BACKLOG.md); proposals are not build authorization.

## Dated decisions and evidence

Measurements belong to their named archives, inputs and hosts; consult each
record's current reproduction instructions and retained historical limits.

- [Latest behavior release: v0.52.0](RELEASE-2026-11-08-v0.52.0.md) and
  [all release notes](../CHANGELOG.md); v0.52.1 is metadata-only.
- [Protocol baseline](PROTOCOL-VALIDATION.md), [serve](SERVE-PROTOCOL-VALIDATION.md),
  [Skills metadata](SKILLS-GUARD-VALIDATION.md) and [doctor](DOCTOR-EVIDENCE-VALIDATION.md).
- [Native clients](NATIVE-CLIENT-VALIDATION.md), [Cursor](CURSOR-CLIENT-VALIDATION.md),
  [Gemini](GEMINI-CLIENT-VALIDATION.md), [managed policy](MANAGED-POLICY-VALIDATION.md)
  and [wrapper identity](WRAPPER-IDENTITY-VALIDATION.md).
- [Artifact review](ARTIFACT-REVIEW-VALIDATION.md), [retained Skills](RETAINED-SKILLS-DECISION.md),
  [native hook lifecycle](NATIVE-PLUGIN-LIFECYCLE.md) and
  [command-hook confinement NO-GO](HOOK-CONFINEMENT-DECISION.md).
- [External evidence deferral](EXTERNAL-EVIDENCE-DECISION.md),
  [ACP trace deferral](ACP-TRACE-DECISION.md) and [2026-11-05 research](RESEARCH-2026-11-05.md).
- Historical [vision](VISION.md), [security roadmap](ROADMAP.md),
  [adoption roadmap](ROADMAP-ADOPTION.md), [hardening plan](SECURITY-HARDENING.md)
  and [preserved contributor archive](history/CLAUDE-2026-11-06.md).
