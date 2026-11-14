# Documentation review — 2026-11-15

Reviewed repository base `4805073f17f40a8fa6c93ce9b07c7b84efef0c3b` and the
maintainer's mcpm notes. This is a documentation/governance review, not a new
runtime security audit, release, native-client measurement or strategy decision.
The selected acceptance criteria remain in [BACKLOG](BACKLOG.md); operating
ownership is described in [maintainer workflow](MAINTAINER-WORKFLOW.md).

## Coverage and method

All **67 tracked Markdown files** at the review base and **59 mcpm Markdown
notes** were inventoried and scanned for navigation, dated/current ownership,
status contradictions and residual edit markers. Current consumer/instruction
surfaces and affected claims were checked against source; dated evidence was
reviewed for identity and scope, not re-executed or independently re-proved.
The inventory below explicitly includes fixture Markdown and the preserved
contributor archive. The two retained non-Markdown note artifacts were identified
as historical scripts; they were not executed or treated as active instructions.

Repository-relative Markdown targets/heading anchors and note wiki-link targets
were checked. Historical roadmap estimates, adoption figures, research claims,
old “next” queues and unchanged release measurements remain dated evidence.
This coverage does not mean every historic claim or external URL was revalidated.
Private board URLs, card details and note contents are intentionally kept out of
this public record.

## Confirmed findings and changes

| Finding | Resolution |
| --- | --- |
| Architecture and current serve assertions still described nine tools after v0.54.0 | Corrected to ten; `src/server/index.ts` registers ten and `scripts/protocol-sandbox/run.mjs` asserts ten in candidate mode. Dated v0.48.0 results remain unchanged. |
| Task-oriented docs index omitted the current audit-report contract | Added the CLI/MCP report link under consumer documentation. |
| Private status/navigation still presented the November 8 development checkpoint and v0.52.0 behavior release as latest | Relabeled those sections historical and linked current release and operational ownership. |
| Nine note metadata statuses remained candidate/open/unreleased despite their retained delivery closeouts | Reconciled metadata to the named delivered slice; retained former status in a dated correction and preserved original body/evidence. |
| One historical note contained a literal failed-edit marker and split/duplicate frontmatter | Reunited existing metadata and preserved the older status as explicit historical provenance. No research result was rewritten. |
| Another historical note had an unquoted colon-bearing YAML scalar that prevented frontmatter parsing | Quoted the unchanged scalar; historical dates, text and decisions remain intact. |
| Planning, private task notes and release history could each be mistaken for the current queue | Added narrow navigation/ownership references. Backlog IDs remain distinct from GitHub issue numbers; historical TODOs remain archived. |

The repository's byte-preserved `docs/history/CLAUDE-2026-11-06.md` has one
relative Markdown target that resolves from the original repository root rather
than its archive directory. This documented archive exception remains unchanged;
its bytes are historical evidence. No other missing repository Markdown targets
or heading anchors were found by the scoped check. No new runtime defect was
established during this documentation review.

## Live delivery snapshot

Read-only GitHub checks on November 15 confirmed:

- [v0.54.0](https://github.com/getmcpm/cli/releases/tag/v0.54.0) published at
  `2026-11-13T16:01:24Z` (November 14 HKT). Annotated tag
  `983e599f571f26d3a2fdbf0ba966a901a31cafbf` peels to release source
  `88bfb58013e639acfbf73081913b2c70ca8c9c56`; the
  [publish run](https://github.com/getmcpm/cli/actions/runs/43458089241) succeeded.
- [Playground #37](https://github.com/getmcpm/guard-playground/pull/37) merged as
  `bab9ad1dbb1dd203108b552a463836eb167f41a2`, and its
  [Pages run](https://github.com/getmcpm/guard-playground/actions/runs/43460401171)
  succeeded on that source. [Guardbench #25](https://github.com/getmcpm/mcp-guardbench/pull/25)
  merged as `13445a84989a1fee1038e82e04e911117a1bc08e`.
- CLI dependency PRs **#331/#351/#352/#354/#355/#358/#359** and playground
  **#36** remained open and separate. CLI had no open issues; project backlog
  numbers therefore must not be turned into fabricated issue links.
- [Documentation closeout #357](https://github.com/getmcpm/cli/pull/357) merged
  as the review base. Its previously queued optional macOS job subsequently
  ended **cancelled**, with no recorded steps; the
  [documentation-head CI run](https://github.com/getmcpm/cli/actions/runs/43463105106)
  reports overall failure while Node 22/24/26 and protocol jobs succeeded.
  Cancellation cause is unverified. “Queued at merge” remains correct historical
  wording; this does not establish a code failure or invalidate the separately
  successful release-source gates. Follow-up must inspect the actual cause and
  intended head before requesting any rerun; no gates were relaxed here.

The [v0.54.0 release record](RELEASE-2026-11-14-v0.54.0.md) remains the owner of
archive authentication, 44 public audit executions, 151 protocol comparisons,
24 new wire observations, 104 retained Skills captures, companion byte identity
and deployed browser evidence. Those are retained release measurements, not
checks repeated by this documentation pass. A green deployment API result alone
does not independently re-prove current served asset bytes.

## Selected tracking boundaries

Use existing IDs and acceptance criteria; do not import every historical idea.
A delivered slice and its broad open parent need separate dispositions:

| Scope | Required acceptance or reopening boundary |
| --- | --- |
| `#131`/`#149` | CLI coverage report v0.53.0 and MCP report v0.54.0 are delivered; broader client/native inventory, installed-byte and ownership coverage remain open. Select/reproduce one remaining problem before implementation. |
| `#141` | Fixed Claude Code and explicit VS Code slices are delivered; named-profile/remote/workspace/other-host coverage remains open. Never infer effective selection or activation from inventory. |
| `#155`, `#122`, `#156` | Track their bounded shipped acceptance, with wrapper authenticity, whole-host policy and further archive-review consumer/value limits intact. |
| `#140`, `#158` | Completed retained-fixture and one-host inline-hook MVPs; no production manifest enforcement, text-skill activation or universal native claim. |
| `#157`, `#159` | Deferred/unbuilt. Reopen only on their original report-value/binding or supplied ACP trace/consumer/privacy prerequisites. A completed gate decision is not a shipped adapter. |
| `#95` | Completed measured experiment with NO-GO for integrating that fixed candidate; a production strict-hook backend remains unbuilt. |
| Maintenance and CI intake | Link actual PRs; reproduce older hypotheses and diagnose cancellation before selecting a fix. Do not invent deadlines, blanket acceptance or permission to merge/release. |

No E7 remote diagnostics, behavioral eval, new scanner/platform, outreach or
historical market hypothesis was promoted by this pass. Dates require an actual
commitment; a merged PR alone is not deployed or verified evidence.

## Verification and limits

Changed Markdown links/anchors, source tool-count claims, YAML frontmatter,
whitespace and note wiki-link targets were checked. Note edits use atomic
replacement and exact-byte readback; retained dated bodies and fixture bytes
were preserved. The malformed duplicate-frontmatter protocol fixture is an
intentional negative test, not a document to repair.

No source/runtime/dependency change, full test suite, package execution, signature
reverification, native VM/client, provider/model call, browser rendering, benchmark
or deployment was performed for this docs-only review. External link health and
Obsidian visual rendering are not comprehensively verified. Temporary audit
receipts are working evidence, not durable release artifacts.

### Final tracking integration review

The new private operational note was reviewed separately from the 59 existing
notes. Independent live Project API readback checked private visibility, configured
fields/views, linked repositories and every imported card's scope, status, source
reference and stop rule. Priorities and target dates remained unset. Corrected a
private-note navigation target, distinguished completed negative experiments from
deferred production work, and corrected the archive-review card's consumer to the
maintainer's actual plugin-update decision. Private card details remain outside
this report; UI rendering and visible board grouping were not verified.

The final contributor instructions, repo-owned development/release skills,
selected backlog and maintainer workflow agree on public criteria versus private
operational ownership. Missing private access does not block public contributions;
tracking state grants no additional implementation, merge or release authority.
The public consumer skill and runtime remain unchanged.

## Complete repository Markdown inventory at the review base

Each file below was included in the inventory/structural scan. Category membership
states its authority, not fresh verification of every statement it contains.
Validation documents can combine current reproduction instructions with explicitly
dated measurements; their original archive/client pins stay separate.

### Instructions and entry points (13)

- [.agents/skills/mcpm-development/SKILL.md](../.agents/skills/mcpm-development/SKILL.md)
- [.agents/skills/mcpm-release/SKILL.md](../.agents/skills/mcpm-release/SKILL.md)
- [.claude/skills/mcpm-development/SKILL.md](../.claude/skills/mcpm-development/SKILL.md)
- [.claude/skills/mcpm-release/SKILL.md](../.claude/skills/mcpm-release/SKILL.md)
- [.github/PULL_REQUEST_TEMPLATE.md](../.github/PULL_REQUEST_TEMPLATE.md)
- [.github/actions/mcpm-verify/README.md](../.github/actions/mcpm-verify/README.md)
- [AGENTS.md](../AGENTS.md)
- [CLAUDE.md](../CLAUDE.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
- [README.md](../README.md)
- [SECURITY.md](../SECURITY.md)
- [skills/mcpm/SKILL.md](../skills/mcpm/SKILL.md)
- [website/README.md](../website/README.md)

### Current contracts, map and selected status (16)

- [docs/AGENT-WORKFLOW.md](AGENT-WORKFLOW.md)
- [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/ARTIFACT-REVIEW.md](ARTIFACT-REVIEW.md)
- [docs/AUDIT-REPORT.md](AUDIT-REPORT.md)
- [docs/BACKLOG.md](BACKLOG.md)
- [docs/CONTRACTS.md](CONTRACTS.md)
- [docs/DISTRIBUTION.md](DISTRIBUTION.md)
- [docs/GUARD.md](GUARD.md)
- [docs/MAINTAINER-WORKFLOW.md](MAINTAINER-WORKFLOW.md)
- [docs/POLICY.md](POLICY.md)
- [docs/PROJECT-SCOPE.md](PROJECT-SCOPE.md)
- [docs/README.md](README.md)
- [docs/SIGNATURES.md](SIGNATURES.md)
- [docs/TRUST.md](TRUST.md)
- [docs/USAGE.md](USAGE.md)
- [docs/owasp-mcp-mapping.md](owasp-mcp-mapping.md)

### Validation and bounded decisions (15)

- [docs/ACP-TRACE-DECISION.md](ACP-TRACE-DECISION.md)
- [docs/ARTIFACT-REVIEW-VALIDATION.md](ARTIFACT-REVIEW-VALIDATION.md)
- [docs/CURSOR-CLIENT-VALIDATION.md](CURSOR-CLIENT-VALIDATION.md)
- [docs/DOCTOR-EVIDENCE-VALIDATION.md](DOCTOR-EVIDENCE-VALIDATION.md)
- [docs/EXTERNAL-EVIDENCE-DECISION.md](EXTERNAL-EVIDENCE-DECISION.md)
- [docs/GEMINI-CLIENT-VALIDATION.md](GEMINI-CLIENT-VALIDATION.md)
- [docs/HOOK-CONFINEMENT-DECISION.md](HOOK-CONFINEMENT-DECISION.md)
- [docs/MANAGED-POLICY-VALIDATION.md](MANAGED-POLICY-VALIDATION.md)
- [docs/NATIVE-CLIENT-VALIDATION.md](NATIVE-CLIENT-VALIDATION.md)
- [docs/NATIVE-PLUGIN-LIFECYCLE.md](NATIVE-PLUGIN-LIFECYCLE.md)
- [docs/PROTOCOL-VALIDATION.md](PROTOCOL-VALIDATION.md)
- [docs/RETAINED-SKILLS-DECISION.md](RETAINED-SKILLS-DECISION.md)
- [docs/SERVE-PROTOCOL-VALIDATION.md](SERVE-PROTOCOL-VALIDATION.md)
- [docs/SKILLS-GUARD-VALIDATION.md](SKILLS-GUARD-VALIDATION.md)
- [docs/WRAPPER-IDENTITY-VALIDATION.md](WRAPPER-IDENTITY-VALIDATION.md)

### Dated release records (8)

- [docs/RELEASE-2026-11-05-v0.49.2.md](RELEASE-2026-11-05-v0.49.2.md)
- [docs/RELEASE-2026-11-05.md](RELEASE-2026-11-05.md)
- [docs/RELEASE-2026-11-06-v0.50.0.md](RELEASE-2026-11-06-v0.50.0.md)
- [docs/RELEASE-2026-11-06-v0.50.1.md](RELEASE-2026-11-06-v0.50.1.md)
- [docs/RELEASE-2026-11-06-v0.51.0.md](RELEASE-2026-11-06-v0.51.0.md)
- [docs/RELEASE-2026-11-08-v0.52.0.md](RELEASE-2026-11-08-v0.52.0.md)
- [docs/RELEASE-2026-11-11-v0.53.0.md](RELEASE-2026-11-11-v0.53.0.md)
- [docs/RELEASE-2026-11-14-v0.54.0.md](RELEASE-2026-11-14-v0.54.0.md)

### Historical research, plans and changelog (9)

- [CHANGELOG.md](../CHANGELOG.md)
- [docs/RESEARCH-2026-11-05.md](RESEARCH-2026-11-05.md)
- [docs/REVIEW-2026-11-05.md](REVIEW-2026-11-05.md)
- [docs/ROADMAP-ADOPTION.md](ROADMAP-ADOPTION.md)
- [docs/ROADMAP.md](ROADMAP.md)
- [docs/SECURITY-HARDENING.md](SECURITY-HARDENING.md)
- [docs/VISION.md](VISION.md)
- [docs/history/CLAUDE-2026-11-06.md](history/CLAUDE-2026-11-06.md)
- [scripts/launch-checklist.md](../scripts/launch-checklist.md)

### Test fixtures (6)

- [scripts/native-client/plugin-lifecycle-fixtures/v1/skills/inert/SKILL.md](../scripts/native-client/plugin-lifecycle-fixtures/v1/skills/inert/SKILL.md)
- [scripts/native-client/plugin-lifecycle-fixtures/v2/skills/inert/SKILL.md](../scripts/native-client/plugin-lifecycle-fixtures/v2/skills/inert/SKILL.md)
- [scripts/protocol-sandbox/skills-fixtures/duplicate-frontmatter.md](../scripts/protocol-sandbox/skills-fixtures/duplicate-frontmatter.md)
- [scripts/protocol-sandbox/skills-fixtures/nested-SKILL.md](../scripts/protocol-sandbox/skills-fixtures/nested-SKILL.md)
- [src/guard/__tests__/fixtures/legitimate-corpus/README.md](../src/guard/__tests__/fixtures/legitimate-corpus/README.md)
- [src/guard/__tests__/fixtures/mcptox/README.md](../src/guard/__tests__/fixtures/mcptox/README.md)
