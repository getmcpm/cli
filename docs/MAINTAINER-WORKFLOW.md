# Maintainer workflow and context

## Current checkpoint — 2026-11-06

Current published CLI: **v0.50.0**. The bounded Claude Code scope inventory from
project backlog #141 shipped; broader host/project coverage remains open.
**#122 managed-policy-aware setup** merged in PR #324 but remains unreleased.
The compatibility follow-up candidate is verified and Astra reviewed; PR/CI,
merge and release are pending. Its [candidate validation](MANAGED-POLICY-VALIDATION.md)
separates the earlier archive checkpoint from the verified follow-up and records
the bounded profile and limits.
See the [active backlog](BACKLOG.md) and
[v0.50.0 release evidence](RELEASE-2026-11-06-v0.50.0.md) for the actual source,
companion matrix, archive verification and proof limits. Historical native
measurements belong to their named versions; this checkpoint is not a new run.

## Instruction and skill loading

[Root AGENTS.md](../AGENTS.md) holds shared current contributor instructions.
Codex discovers it natively; [CLAUDE.md](../CLAUDE.md) explicitly imports it with
`@AGENTS.md`, so Claude does not need a second copy of the shared instructions.
Ordinary Markdown links are references to read when relevant, not auto-imports.

| Workflow | Canonical repo source | Claude discovery entry |
| --- | --- | --- |
| Development | [.agents/skills/mcpm-development/SKILL.md](../.agents/skills/mcpm-development/SKILL.md) | [.claude/skills/mcpm-development/SKILL.md](../.claude/skills/mcpm-development/SKILL.md) |
| Release | [.agents/skills/mcpm-release/SKILL.md](../.agents/skills/mcpm-release/SKILL.md) | [.claude/skills/mcpm-release/SKILL.md](../.claude/skills/mcpm-release/SKILL.md) |

Codex scans repo `.agents/skills`; Claude scans `.claude/skills`. The Claude
entries are small ordinary files that instruct the agent to read the canonical
file. They are repo-only references, not self-contained distributions or symlinks
(which can be troublesome on Windows). Invoke the selected host skill, or ask
explicitly to read the canonical repo path when discovery differs. Personal
same-name skills can shadow project skills in Claude (enterprise > personal >
project); Codex may show duplicates. Choose the explicit repo source when in doubt;
do not overwrite personal skills to fix discovery. Loading depends on host/version,
not just file presence; a file/link check is not an actual host-loading test.

The public [mcpm usage skill](../skills/mcpm/SKILL.md) stays self-contained at its
distribution path, separately from both maintainer workflows. npm ships `dist`
only. See [agent workflow/distribution and behavioral scenarios](AGENT-WORKFLOW.md).
No global settings, hooks, tool grants or installer are part of this layout.

Loading references checked 2026-11-06:
[Codex AGENTS.md](https://developers.openai.com/codex/guides/agents-md/),
[Codex skills](https://developers.openai.com/codex/skills/),
[Claude shared memory import](https://code.claude.com/docs/en/memory#share-one-file-with-other-coding-tools),
[Claude skill locations](https://code.claude.com/docs/en/skills#choose-where-skills-load).

### Measured loading checkpoint — 2026-11-06

Local Codex 0.166.0 `skills/list` discovered both canonical maintainer skills;
an ephemeral thread reported root AGENTS.md as its instruction source. Claude
Code 2.1.293 SDK initialization discovered both project skills and
`get_context_usage` listed root CLAUDE.md plus AGENTS.md, with no historical
archive. Probes used disposable homes, OS-level network denial, no credentials,
no model turns and no API usage (`apiUsage: null`). Wrapper targets were checked
statically. This proves discovery/import only, not model compliance, following
the wrapper reference or Windows behavior. Local receipt:
`/private/tmp/mcpm-agent-host-evidence-20261106/sol-candidate.json` (temporary).

## Task references

- [CONTRIBUTING](../CONTRIBUTING.md): toolchain, source checks and release smoke.
- [Contracts](CONTRACTS.md), [architecture](ARCHITECTURE.md), [guard](GUARD.md),
  [policy](POLICY.md), [security delivery status](SECURITY-HARDENING.md) and
  [security reporting](../SECURITY.md): maintained behavior and boundaries.
- [Protocol baseline](PROTOCOL-VALIDATION.md), [candidate serve](SERVE-PROTOCOL-VALIDATION.md),
  [Skills metadata](SKILLS-GUARD-VALIDATION.md), [doctor evidence](DOCTOR-EVIDENCE-VALIDATION.md),
  [native clients](NATIVE-CLIENT-VALIDATION.md), [Cursor](CURSOR-CLIENT-VALIDATION.md)
  and [Gemini](GEMINI-CLIENT-VALIDATION.md): choose evidence for the changed surface.
- [Project scope](PROJECT-SCOPE.md): read-only inventory coverage and unknowns.
  [Research](RESEARCH-2026-11-05.md) explains the current selected queue;
  [ROADMAP](ROADMAP.md) and [adoption roadmap](ROADMAP-ADOPTION.md) retain history.

## Historical context

The complete former 1,008-line CLAUDE.md is preserved **byte-for-byte** in
[CLAUDE-2026-11-06.md](history/CLAUDE-2026-11-06.md), from main source
`d6de8bf927ba7cd6ba01be005a7055d061a11458`. It is a historical archive, not active
instructions: its old release exceptions, expired freeze, proposed milestones,
market figures, local paths and tool setup are not present authorization or fresh
verification. Read it only when a dated decision or older release evidence matters.
Its relative links retain original bytes and may need resolving from the repo root.

Still-active decisions are summarized in AGENTS.md and the maintained references:
local-first/no telemetry, deterministic defaults without another model/subscription,
trust and guard as the product, config preservation and evidence-before-claims.
The 2026-08-31 external-scanner decision (corrected 2026-09-08) remains relevant:
Snyk agent-scan can accept a coordinate but executes servers and requires account/API
access, so it does not fit mcpm's local, non-executing metadata-scanner seam.
Historical market/competitor statistics require current sourcing before reuse;
Morphisec's `drp-compliance-sdk` was a lab construction, not an in-the-wild incident.
