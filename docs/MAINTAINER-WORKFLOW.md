# Maintainer workflow and context

## Current checkpoint — 2026-11-20

The latest published CLI is **v0.54.4**. Read-only `sync`, `list` and `diff`
report unreadable client configs and retain results from readable configs. The
[release record](RELEASE-2026-11-20-v0.54.4.md) includes package and protocol
verification and links to the companion updates.

The bounded `#131`/`#149` report slice shipped; broader audit and host coverage
remain open. Earlier VS Code/Copilot `scope` evidence remains bound to its named
release/client; Claude Code remains the default and broader `#141` stays open.

The [active backlog](BACKLOG.md) owns selected work and acceptance. Recent bounded
MVP/decision records cover [archive review](ARTIFACT-REVIEW.md),
[retained Skills](RETAINED-SKILLS-DECISION.md),
[native hook lifecycle](NATIVE-PLUGIN-LIFECYCLE.md),
[hook confinement NO-GO](HOOK-CONFINEMENT-DECISION.md),
[external evidence deferral](EXTERNAL-EVIDENCE-DECISION.md) and
[ACP trace deferral](ACP-TRACE-DECISION.md). Their measurements remain bound to
named inputs/hosts, rather than transferring to every subsequent package.
The v0.54.5 candidate includes the merged Ora update (#331), other dependency
updates, and corrected `mcpm init` completion help. Contributor skills remain
repo-only.

## Delivery tracking

For maintainer-owned work with authorized access, use the existing private
**mcpm Delivery** GitHub Project in the getmcpm organization. It follows the
Credspan delivery pattern with private planning issues as the durable execution
records. Read that repository's `AGENTS.md` and `PROCESS.md`, alongside the shared
`project-workflow` skill when available. Public selected criteria stay in
[BACKLOG](BACKLOG.md); private issues retain assignments, blockers, handoffs and
source evidence, and the Project displays their operational fields. GitHub
code/PRs/checks own actual implementation and merge state; dated validation/release records own measured proof. Obsidian
retains private context/history and the board link; chat work-state is a working aid.
See the [November 15 documentation review](DOCS-REVIEW-2026-11-15.md).

Use **Backlog → Ready → Building → Review → Done**, with **Planned, Implemented,
Merged, Deployed, Verified** recorded separately as delivery evidence. Ready needs
bounded scope/acceptance and cleared gates. Done applies only to the card's named
acceptance: a verified negative experiment is not a production capability, and a
shipped slice never closes its broad remaining-scope card. Keep #157/#159 consumer
gates and #95 NO-GO explicit. Leave dates/priorities unset until triage/commitment.

At start, search existing private issues/cards and reconcile the scoped task with
public criteria. Record one active agent/chat owner before implementation; direct
user assignment establishes ownership absent a conflict, while autonomous queue
allocation needs a conditional claim or named coordinator. Read current task
content before updating and preserve user edits. After meaningful changes, record
exact review/head/check/tag/archive/deployment evidence and remaining limits, then
read back issue state and Project fields. Keep public backlog IDs distinct from
private issue numbers; completed bounded slices do not close broader work.
Do not create duplicate tracking, expose private board/card/vault details in public
PRs, or infer implementation/merge/release/provider-spend permission from a card.
Public contributions must not require access to private maintainer tracking.

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
  [policy](POLICY.md) and [security reporting](../SECURITY.md): maintained behavior
  and boundaries. [Security hardening](SECURITY-HARDENING.md) retains a dated plan.
- [Protocol baseline](PROTOCOL-VALIDATION.md), [candidate serve](SERVE-PROTOCOL-VALIDATION.md),
  [Skills metadata](SKILLS-GUARD-VALIDATION.md), [doctor evidence](DOCTOR-EVIDENCE-VALIDATION.md),
  [native clients](NATIVE-CLIENT-VALIDATION.md), [Cursor](CURSOR-CLIENT-VALIDATION.md)
  and [Gemini](GEMINI-CLIENT-VALIDATION.md): choose evidence for the changed surface.
- [Coverage-aware audit](AUDIT-REPORT.md): opt-in CLI store/report contract; legacy audit outputs remain separate.
- [Project scope](PROJECT-SCOPE.md): read-only inventory coverage and unknowns.
  [Artifact review](ARTIFACT-REVIEW.md) and [candidate evidence](ARTIFACT-REVIEW-VALIDATION.md):
  archive/profile boundaries, concrete consumer decision and artifact attribution.
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
