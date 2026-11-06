# Active trust and DevX backlog — 2026-11-06

This is the current, deliberately selected queue, aligned with the project
Obsidian backlog. **#IDs are project backlog IDs, not GitHub issue numbers.** It
does not replace the dated history or claim every older hypothesis was rechecked.
Research proposals are not build/release authorization. Sources and scope are in
[the research report](RESEARCH-2026-11-05.md).

[PR #308](https://github.com/getmcpm/cli/pull/308) merged the reviewed
configuration, removal/store, scanner, SRI, prior-lock and import/export fixes.
They shipped in [v0.49.1](RELEASE-2026-11-05.md). Do not schedule those same
defects again or close the whole #123/#131/#149/#150 group because one slice is
fixed. The native doctor suite merged in #307; its recorded native measurements
used the published v0.49.0 archive.

## Ordered queue

| Order | ID | Scope/status | Dependency |
| --- | --- | --- | --- |
| 1 | #156 | New: local skill/plugin change-review receipt; experiment | #141; one consumer; fixed file/host scope |
| 2 | #157 | New: pinned external-report ingestion; conditional | #156 or a concrete multi-tool support case |
| 3 | #140 | Existing: remaining Skills manifest/byte verification | Actual consumer; pinned beta revision |
| 4 | #158 | New: native artifact activation/drift measurement; conditional | #156 demand; disposable profile/host access |
| Later | #159 | New: offline ACP v1 evidence spike; demand-gated | One real trace consumer; stable interpretation |
| Later | #95 | Existing: hook confinement GO/NO-GO experiment | Measured cohort and restrictive policy |

Effort ranges below are engineering judgments for one contributor including tests
and documentation, not delivery promises. Native setup, access and review delays
are excluded. Do not implement the whole queue in parallel.

## #155 — Honest wrapper identity and protection status

**Status:** shipped in [v0.49.2](RELEASE-2026-11-05-v0.49.2.md), after #312 and
Astra review/fixes. Published-archive SDK and native Linux launcher checks passed.
Static-recognition/binary-authentication limits remain explicit. **User/problem:** a plain server can
be misidentified as already guarded, undermining enrollment/status evidence.
**MVP:** define recognized wrapper, plain entry and ambiguous/invalid states;
handle original launch forms without silently rewriting or double-wrapping them.

**Acceptance:** registry-controlled lookalikes and arbitrary node scripts never
receive guarded status or skip enrollment. npm/npx/global/dev-checkout and Windows
forms, old Node paths, malformed wraps, path moves and enable/disable/update round
trips have explicit fixtures. Ambiguous state produces a clear refusal/repair plan;
original settings/secrets survive. Test a named real client launch before claiming
effective protection. **Non-goals:** binary authentication or general command
attestation. **Effort:** 3–6 days, revised after the compatibility inventory.
**Risk:** a partial predicate fix can leave false positives or break old wraps.

## #141 — Project exposure and scope inventory

**Status:** the bounded Claude Code `mcpm scope <project-root> [--json]` slice shipped in [v0.50.0](RELEASE-2026-11-06-v0.50.0.md) after #315 and Astra review/fixes. Seven actual published CLI scope cases and 87 protocol comparisons passed. The broader #141 item remains open: additional host dialects remain unimplemented/unmeasured. See [scope documentation](PROJECT-SCOPE.md). **User/problem:** global-only evidence
can miss project configuration and precedence. **MVP:** explicit project root,
one host profile first, read-only project MCP entries and applicable instruction
files; identify origin, scope, shadowing and unreadable/unsupported coverage.

**Acceptance:** parent/workspace paths, symlink escapes, duplicate names, malformed
files, denied access, secret placeholders and unknown host versions cannot become
empty healthy state. Output separates configured from observed-loaded/enforced;
no commands, hooks, credential helpers or servers run. Start with Claude Code;
add another dialect only with fixtures and distinct semantics. **Dependencies:**
#155 for guarded labels; #131/#149 coverage reporting. **Non-goals:** project
writes, recursive whole-home discovery or native policy reimplementation.
**Effort:** 2–4 days. **Risk:** scope precedence varies by host/version.

## #122 — Managed-policy-aware setup and wrap plan

**Status:** bounded Claude Code MVP shipped in [v0.50.1](RELEASE-2026-11-06-v0.50.1.md), after #324/#325 and Astra review/fixes. Actual published archive passed 22 native policy cases, three initialization cases and 87 protocol checks. Whole-host coverage and legacy-wrapper migration limits remain explicit in the [projection record](MANAGED-POLICY-VALIDATION.md). **User/problem:** changing the command to a
wrapper can change a client's allow/deny decision. **MVP:** read one supported,
versioned policy source set and compare current/proposed launches before writes.
Report exact reason and uncertainty; preserve native restrictions.

**Acceptance:** allow, deny, empty/unset rules, expanded variables, managed
exceptions, unreadable policy and wrapper argv have fixtures; pinned native tests
prove denied commands remain undispatched and allowed flows remain usable.
Unsupported policy planes are unknown and never silently permitted. **Dependencies:**
#155 and target-version semantics. **Non-goals:** editing managed controls,
weakening restrictions or a cross-vendor enterprise engine. **Effort:** 3–6 days
plus access/native-test delays. **Risk:** policy definitions are client-specific;
reproduce the current matching behavior before selecting the fix.
[Native command matching](https://code.claude.com/docs/en/managed-mcp),
[versioned VS Code policy scope](https://code.visualstudio.com/docs/enterprise/manage-ai-settings).

## #156 — Local skill/plugin change-review receipt

**Status:** new, bounded beyond-MCP experiment. **User/problem:** a developer
reviewing an update needs to understand changed instructions and executable
components across scope/cache layers. **MVP:** compare two explicitly supplied
local snapshots of Agent Skills and one Claude plugin dialect. Reuse existing
inspection primitives and native validators where useful; identify source, exact
changed files, declared components, referenced scripts and interpretation limits.

**Acceptance:** root containment, symlinks, missing resources, alternate/inline
components, duplicate names, unknown versions and incomplete manifests have
fixtures. Bind findings and hashes to the same bytes read; changes during the
scan produce an incomplete result, not a clean snapshot. Distinguish
configured/cached/loaded/unknown; do not guess runtime
activation or fully infer commands from prose. No network, install, scripts,
permission grants, credential-store reads or automatic native-validator execution.
Reports omit credential values; withheld sensitive inputs remain coverage gaps,
and hashing is not described as secret redaction. One consumer uses the report to
decide a concrete update; otherwise stop or integrate native/APM tooling.
**Dependencies:** #141; a review workflow/consumer. **Non-goals:** marketplace,
generic scanner, installer, universal safety score or host enforcement.
**Effort:** 2–4 days for the experiment. **Risk:** native tools already cover much
of this; value is unproven. [Format](https://agentskills.io/specification),
[native plugin lifecycle](https://code.claude.com/docs/en/plugins/loading).

## #157 — Versioned external evidence ingestion

**Status:** new, conditional delta to existing E6/E10a reports. **User/problem:**
users combining tools need findings tied to the exact analyzed artifact and
analysis coverage. **MVP:** accept one already-produced local report from one
pinned scanner; preserve original tool/version, digest, severity, mode and gaps.

**Acceptance:** wrong/stale digest, unknown format/version, malformed/truncated
results, skipped resources, unavailable analyzers and provider-dependent phases
cannot become clean. Retain original evidence locally and reject unsupported
contracts. Measure incremental findings and false-positive review cost on a
labeled fixture set. **Dependencies:** a concrete multi-tool use case, schema,
redaction and retention policy. **Non-goals:** auto-running scanners, silent
uploads/LLM calls, native trust-floor credit, a generic adapter framework or an
aggregate safety score. **Effort:** 2–4 days for one adapter. **Risk:** unstable
vendor contracts and hidden egress. [Snyk contract caution](https://github.com/snyk/agent-scan),
[SkillSpector scope](https://github.com/NVIDIA/SkillSpector).

## #140 — Retained Skills manifest and content verification

**Status:** existing, partially shipped: metadata inspection is in v0.48.1;
manifest/byte/identity and loading boundaries remain separate. **MVP:** only with
a concrete consumer, validate retained static manifests and raw-byte digest/size
relationships in pinned beta fixtures, keyed by origin plus URI.

**Acceptance:** missing/rotated/added files, dynamic or incomplete manifests,
cross-origin identity confusion and digest changes cannot inherit a clean result;
unknowns remain explicit. Re-run both protocol eras. **Non-goals:** trusting a
server hash as publisher identity, fetching unbounded archives, approval grants
or claiming host-side loading enforcement. **Effort:** 3–5 days after the fixture
contract. **Risk:** Beta revisions/host support change. [Authoritative repository](https://github.com/modelcontextprotocol/ext-skills).

## #158 — Native artifact activation and update-drift evidence

**Status:** new, conditional follow-up to #156; distinct from MCP doctor tests.
**User/problem:** installed/cached plugin bytes can differ from running-session
state. **MVP:** one pinned host, synthetic plugin/skill, disposable profile and
deterministic component marker; observe update/reload/disable/restart identity.

**Acceptance:** receipts name exact loaded versions and scoped components; no
host credentials/profiles/shared folders. Unobserved text-skill activation remains
unknown if proving it requires model access. One component's marker cannot certify
all bundled artifacts. **Dependencies:** demonstrated #156 need, host access;
separate explicit provider spend if required. **Non-goals:** live profile changes,
universal host claims or default-consent bypass. **Effort:** 3–6 days plus setup.
**Risk:** lifecycle differs by component/version. [Loading reference](https://code.claude.com/docs/en/plugins/loading).

## #159 — Offline ACP permission/cancellation evidence spike

**Status:** new research candidate, not an active runtime commitment.
**User/problem:** a concrete ACP consumer may need to explain permission and
cancellation handling across captured traces. **MVP:** one supplied, value-redacted
ACP v1 trace and fixture set; check correlation, denied/cancelled outcomes and
missing evidence without connecting to an agent.

**Acceptance:** malformed/unknown revisions, missing replies and partial traces
remain incomplete; client/agent asserted identities are not security credentials.
Stop if no consumer needs this beyond existing logs. **Dependencies:** explicit
trace scope and retention limits. **Non-goals:** v2 Draft implementation, live
proxy, agent sandbox, A2A bridge or delegation broker. **Effort:** 1–3 days for a
spike. **Risk:** semantic drift and privacy in traces. [ACP v1 security](https://agentclientprotocol.com/protocol/v1/security).

## #95 — Hook confinement decision experiment

Existing conditional experiment, not a new benchmark or production runtime.
Select a small authorized command-hook cohort, compare useful benign work against
sensitive-read, egress, out-of-root-write, child escape and cancellation fixtures
in a disposable environment. Separate command hooks from HTTP/MCP/prompt/agent
handlers. Record real breakage and deny behavior before deciding to build or
integrate a backend; stop if useful policy must be broadened until it is ineffective.
**Effort:** 3–5 days for measurement; productionization unestimated. No live secrets
or universal containment claim. [Hook kinds and lifecycle](https://code.claude.com/docs/en/hooks).

## Maintenance, prerequisites and explicit deferrals

- #131/#149/#150: loud coverage and project ownership remain; #308 fixes only
  named slices. Import/export warnings are not a machine-readable completeness
  contract or transactional writes.
- #112/#124/#125/#126/#127: prior policy/concurrency, EPIPE/EOF, pin-property and
  confinement hypotheses remain open; reproduce each before assigning scope.
- #142: watch protocol/extension stages and pin revisions; current Skills is Beta.
  Conflicting Server Card sources remain unresolved, not Stable.
- E7: remote OAuth metadata diagnostics only after a real support case, with
  opt-in destination, DNS/redirect/size/time boundaries and no credentials/login.
- Usage-skill behavioral eval: use existing native eval facilities for one concrete
  task; authorize any provider spend separately. No new eval platform or claims of
  accuracy/token savings from deterministic transport tests.
- A2A, browser/delegation enforcement, HTTP guard, new installer/marketplace,
  hosted control plane, rebranding and paid decision-provider integration remain
  deferred. Existing vendor capabilities and user demand must be checked before
  promoting any of them.
