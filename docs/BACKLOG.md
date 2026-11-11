# Active trust and DevX backlog — 2026-11-08

This is the current, deliberately selected queue, aligned with the project
Obsidian backlog. **#IDs are project backlog IDs, not GitHub issue numbers.** It
does not replace the dated history or claim every older hypothesis was rechecked.
Research proposals are not build/release authorization. Sources and scope are in
[the research report](RESEARCH-2026-11-05.md).

[PR #308](https://github.com/getmcpm/cli/pull/308) merged the reviewed
configuration, removal/store, scanner, SRI, prior-lock and import/export fixes.
They shipped in [v0.49.1](RELEASE-2026-11-05.md). Do not schedule those same
defects again or close the whole `#123`/`#131`/`#149`/`#150` group because one slice is
fixed. The native doctor suite merged in #307; its recorded native measurements
used the published v0.49.0 archive.

## Ordered queue

| Order | ID | Scope/status | Dependency |
| --- | --- | --- | --- |
| Shipped | `#156` | Bounded archive-only receipt in v0.51.0; one-consumer gate met | Expansion retains consumer/value stop rule |
| Deferred | `#157` | Consumer gate evaluated for mcpm's own development/release workflow; adapter unbuilt | Artifact-bound contract and measured incremental value still required |
| Merged PR #333 | `#140` | Full retained Skills fixture MVP for the existing release-harness consumer | Pinned Beta; both archive matrices, independent replay/readback and maintainer acceptance |
| Merged PR #334 | `#158` | Native inline-hook activation/drift experiment | Eight observations/75 checks; independent bindings and maintainer acceptance; scoped evidence below |
| Deferred/unbuilt | `#159` | Offline ACP v1 trace spike; consumer gate evaluated | Current workflow has MCP/native evidence; no supplied ACP trace or concrete ACP-specific review question |
| Measured NO-GO | `#95` | Bounded command-hook confinement decision experiment; production integration unbuilt | Three of five useful cases compatible; all selected effects denied; detached cancellation limitation |

Effort ranges below are engineering judgments for one contributor including tests
and documentation, not delivery promises. Native setup, access and review delays
are excluded. Do not implement the whole queue in parallel.

## `#155` — Honest wrapper identity and protection status

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

## `#141` — Project exposure and scope inventory

**Status:** the bounded Claude Code `mcpm scope <project-root> [--json]` slice shipped in [v0.50.0](RELEASE-2026-11-06-v0.50.0.md) after #315 and Astra review/fixes. Seven actual published CLI scope cases and 87 protocol comparisons passed. Claude Code remains the default; the explicit VS Code slice below shipped separately, and broader profile/host coverage remains open. See [scope documentation](PROJECT-SCOPE.md). **User/problem:** global-only evidence
can miss project configuration and precedence. **MVP:** explicit project root,
one host profile first, read-only project MCP entries and applicable instruction
files; identify origin, scope, shadowing and unreadable/unsupported coverage.

The bounded VS Code extension shipped in [v0.52.0](RELEASE-2026-11-08-v0.52.0.md):
explicit `--client vscode` inventories four fixed VS Code/Copilot origins with
format-specific parsing and instruction metadata. Duplicate names do not become
a cross-harness winner. Candidate and published evidence retain separate archive
identities. Remaining named-profile, remote, workspace-file and other-host
coverage stays explicit in [the scope contract](PROJECT-SCOPE.md).
The broader `#141` scope remains open.

**Acceptance:** parent/workspace paths, symlink escapes, duplicate names, malformed
files, denied access, secret placeholders and unknown host versions cannot become
empty healthy state. Output separates configured from observed-loaded/enforced;
no commands, hooks, credential helpers or servers run. Start with Claude Code;
add another dialect only with fixtures and distinct semantics. **Dependencies:**
`#155` for guarded labels; `#131`/`#149` coverage reporting. **Non-goals:** project
writes, recursive whole-home discovery or native policy reimplementation.
**Effort:** 2–4 days. **Risk:** scope precedence varies by host/version.

## `#122` — Managed-policy-aware setup and wrap plan

**Status:** bounded Claude Code MVP shipped in [v0.50.1](RELEASE-2026-11-06-v0.50.1.md), after #324/#325 and Astra review/fixes. Actual published archive passed 22 native policy cases, three initialization cases and 87 protocol checks. Whole-host coverage and legacy-wrapper migration limits remain explicit in the [projection record](MANAGED-POLICY-VALIDATION.md). **User/problem:** changing the command to a
wrapper can change a client's allow/deny decision. **MVP:** read one supported,
versioned policy source set and compare current/proposed launches before writes.
Report exact reason and uncertainty; preserve native restrictions.

**Acceptance:** allow, deny, empty/unset rules, expanded variables, managed
exceptions, unreadable policy and wrapper argv have fixtures; pinned native tests
prove denied commands remain undispatched and allowed flows remain usable.
Unsupported policy planes are unknown and never silently permitted. **Dependencies:**
`#155` and target-version semantics. **Non-goals:** editing managed controls,
weakening restrictions or a cross-vendor enterprise engine. **Effort:** 3–6 days
plus access/native-test delays. **Risk:** policy definitions are client-specific;
reproduce the current matching behavior before selecting the fix.
[Native command matching](https://code.claude.com/docs/en/managed-mcp),
[versioned VS Code policy scope](https://code.visualstudio.com/docs/enterprise/manage-ai-settings).

## `#156` — Local skill/plugin change-review receipt

**Status:** bounded archive-only command shipped in
[v0.51.0](RELEASE-2026-11-06-v0.51.0.md), through Sol implementation and Astra
independent review/fixes. The actual npm archive passed authentication,
clean-install smoke, 87 protocol checks and both real consumer comparisons with
exact runtime/input/member bindings. Both consumer reports correctly returned
incomplete coverage; the maintainer retained reviewed Ponytail 5.3.3 source
using the receipt plus manual review. No global update, native activation or
safety approval occurred. Further expansion retains the consumer/value stop rule.
See the [profile](ARTIFACT-REVIEW.md) and
[candidate history](ARTIFACT-REVIEW-VALIDATION.md).

**User/problem:** a developer
reviewing an update needs to understand changed instructions and executable
components across scope/cache layers. **MVP:** compare two explicitly supplied
local snapshots of Agent Skills and one Claude plugin dialect. The implemented
input is two explicit uncompressed USTAR00 archives; directory inputs are refused
before child reads, and archive member paths never reach the filesystem. Reuse existing
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
and hashing is not described as secret redaction. The one-consumer acceptance
gate is met for the bounded experiment: the receipt bound actual source-snapshot
bytes/modes to declarations, references and coverage gaps before the maintainer's
concrete retain/rollback decision. Both real reports exited 1 with incomplete
coverage; manual semantic review remained necessary. This does not demonstrate
general demand, time savings, superiority over native/Git/APM workflows, safety
or activation. Further expansion retains the consumer/value stop rule.
**Dependencies:** `#141`; a review workflow/consumer. **Non-goals:** marketplace,
generic scanner, installer, universal safety score or host enforcement.
**Effort:** original estimate 2–4 days for the experiment. **Risk:** native tools
already cover much of this; repeat use and wider value remain unproven.
[Format](https://agentskills.io/specification),
[native plugin lifecycle](https://code.claude.com/docs/en/plugins/loading).

## `#157` — Versioned external evidence ingestion

**Status:** deferred/unbuilt after the
[2026-11-07 consumer-gate evaluation](EXTERNAL-EVIDENCE-DECISION.md) against
mcpm's own development/release workflow. The maintainer is a concrete consumer
of existing CodeQL/Scorecard, SBOM/provenance and release evidence. An actual
Scorecard SARIF was inspected; ingestion has no demonstrated incremental
labeled findings/false-positive review-cost benefit yet, and its source binding,
coverage, redaction and retention contract is incomplete. No runtime code or
release follows this decision. E6/E10a are existing roadmap proposals, not
shipped reports. **User/problem:**
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

## `#140` — Retained Skills manifest and content verification

**Status:** existing, partially shipped: metadata inspection is in v0.48.1.
The bounded fixture MVP merged in PR #333 (`58d6727`) after all nine CI checks; no npm release was needed.
The [retained-fixture MVP](RETAINED-SKILLS-DECISION.md) extends the actual
release-harness consumer beyond its original single-file consistency assertions.
It checks retained origin/URI identity, every declared resource's raw bytes,
held/refreshed state and explicit incomplete coverage against pinned Beta
fixtures. Both actual SDK/direct/guarded archive matrices passed 139 comparisons;
independent replay/readback and maintainer acceptance cover the expected nonclean
outcomes as well as complete declared-set cases. This is the fixture-scoped MVP;
no new public CLI or
production guard manifest-enforcement claim is required or implemented.
Manifest/byte/identity and loading boundaries remain separate. **MVP:** only with
a concrete consumer, validate retained static manifests and raw-byte digest/size
relationships in pinned beta fixtures, keyed by origin plus URI.

**Acceptance:** missing/rotated/added files, dynamic or incomplete manifests,
cross-origin identity confusion and digest changes cannot inherit a clean result;
unknowns remain explicit. Re-run both protocol eras. **Non-goals:** trusting a
server hash as publisher identity, fetching unbounded archives, approval grants
or claiming host-side loading enforcement. **Effort:** 3–5 days after the fixture
contract. **Risk:** Beta revisions/host support change. [Authoritative repository](https://github.com/modelcontextprotocol/ext-skills).

## `#158` — Native artifact activation and update-drift evidence

**Validated bounded MVP:** the [Claude inline-hook experiment](NATIVE-PLUGIN-LIFECYCLE.md) passed eight source-bound native observations (three clean processes, zero API requests/turns/cost) and 75 native self-checks. Independent final raw/image/source/config bindings passed and the maintainer accepted the scoped evidence. Implementation and limits below retain the measured fixture scope.

**Status:** the bounded fixture MVP merged in PR #334 (`117966d`) after all nine
CI checks, without an npm release or companion repin. The original conditional
follow-up to `#156` is distinct from MCP doctor tests.
**User/problem:** installed/cached plugin bytes can differ from running-session
state. **MVP:** one pinned host, synthetic plugin/skill, disposable profile and
deterministic component marker; observe update/reload/disable/restart identity.

**Acceptance:** receipts name exact loaded versions and scoped components; no
host credentials/profiles/shared folders. Unobserved text-skill activation remains
unknown if proving it requires model access. One component's marker cannot certify
all bundled artifacts. **Dependencies:** demonstrated `#156` need, host access;
separate explicit provider spend if required. **Non-goals:** live profile changes,
universal host claims or default-consent bypass. **Effort:** 3–6 days plus setup.
**Risk:** lifecycle differs by component/version. [Loading reference](https://code.claude.com/docs/en/plugins/loading).

## `#159` — Offline ACP permission/cancellation evidence spike

**Status:** the [current-workflow consumer gate](ACP-TRACE-DECISION.md) was
evaluated; the offline ACP spike remains deferred and unbuilt. A real
permission/cancellation review consumer exists, but its inspected streams are
MCP and Claude native/SDK. Reopen for a concrete ACP trace review, including a
one-off need, with the supplied trace and retention scope below.
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

## `#95` — Hook confinement decision experiment

Existing conditional experiment, not a new benchmark or production runtime.
**Status:** the [bounded experiment](HOOK-CONFINEMENT-DECISION.md) measured mcpm's
own development/release command fixtures on macOS 27.3 with a separate strict
policy. All five unconfined cases worked; strict syntax/test/pack worked, while
both CLI inspect cases failed during user-info startup. All selected sensitive
effects were denied with positive controls, but the detached grandchild continued
work after group cancellation before its separate bounded self-exit. Independent
raw/input replay supports NO-GO for integrating this candidate. The experiment
is complete; a production strict-hook backend remains unbuilt. Original scope
and stop rule remain:
Select a small authorized command-hook cohort, compare useful benign work against
sensitive-read, egress, out-of-root-write, child escape and cancellation fixtures
in a disposable environment. Separate command hooks from HTTP/MCP/prompt/agent
handlers. Record real breakage and deny behavior before deciding to build or
integrate a backend; stop if useful policy must be broadened until it is ineffective.
**Effort:** 3–5 days for measurement; productionization unestimated. No live secrets
or universal containment claim. [Hook kinds and lifecycle](https://code.claude.com/docs/en/hooks).

## Maintenance, prerequisites and explicit deferrals

- `#131`/`#149`: the bounded CLI-only `audit --report-json` slice is implemented
  for review, with fixed mcpm-store inventory, latest metadata, explicit check
  states and separate empty/incomplete outcomes; see [contract](AUDIT-REPORT.md).
  Legacy audit JSON/SARIF/MCP remain unchanged. This does not close broad audit,
  native/client discovery, installed-byte or project-ownership coverage.
- `#150`: project ownership remains; #308 fixes only named slices. Import/export warnings are not a machine-readable completeness
  contract or transactional writes.
- `#112`/`#124`/`#125`/`#126`/`#127`: prior policy/concurrency, EPIPE/EOF, pin-property and
  confinement hypotheses remain open; reproduce each before assigning scope.
- `#142`: watch protocol/extension stages and pin revisions; current Skills is Beta.
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
