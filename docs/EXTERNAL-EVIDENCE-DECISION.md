# #157 external evidence consumer gate — 2026-11-07

**Decision: defer the adapter; no runtime implementation or release.** Evaluate
against mcpm's own development/release workflow, as requested. The maintainer is
a concrete report consumer: decide whether a reviewed source/archive is ready
to merge/release and retain the reasons and limits. Existing external reports
already serve that workflow. The missing gate is demonstrated value from bringing
one of them into mcpm, with an artifact-bound contract and measured incremental
findings/false-positive review cost. This is a completed decision checkpoint,
not shipped #157 functionality or evidence that no consumer exists.

## Existing consumers and evidence

Inspected source `288f71f5eb85f96171980a51be42d8262597e789`, the existing
hosted results below and the [v0.51.0 release record](RELEASE-2026-11-06-v0.51.0.md).
Only already-produced public reports/metadata were retrieved. No scanner,
workflow, provider/model, native client or credential store was invoked.

| Existing input | Current consumer and observed boundary |
| --- | --- |
| CI and hosted CodeQL | Maintainer checks the exact PR/source head before merge. Main's [CodeQL run](https://github.com/getmcpm/cli/actions/runs/42205739649) succeeded. Hosted analyses report CodeQL 2.27.4, the exact main SHA, JavaScript/TypeScript 6 results/87 rules and Actions 0/17, with empty error/warning fields. These are result counts, not six confirmed vulnerabilities or whole-project safety. The Actions artifact list is empty; hosted analyses still exist. |
| OpenSSF Scorecard SARIF | [The workflow](../.github/workflows/scorecard.yml) already uploads to GitHub code scanning and publishes Scorecard results. The maintainer and repository reviewers consume project posture directly. [Run 42205740781](https://github.com/getmcpm/cli/actions/runs/42205740781) produced the inspected report bound through artifact metadata to main. It contains three findings; a successful job does not mean no findings. |
| CycloneDX SBOM and Sigstore bundle | [Publish](../.github/workflows/publish.yml) attaches these best-effort assets after npm publication. The release workflow consumes the original bytes/signature for build-evidence review. Both assets currently exist on [v0.51.0](https://github.com/getmcpm/cli/releases/tag/v0.51.0); metadata availability is not a fresh signature verification. The release record separately documents prior signature/tamper rejection. An SBOM is an inventory, not a scanner verdict about a skill/plugin or a clean release. |
| npm provenance and actual package bytes | The [release workflow](../.agents/skills/mcpm-release/SKILL.md) already requires archive SRI/subject/source/issuer/SAN verification. The v0.51.0 record retains those outcomes. mcpm's shipped `verify --json` also has its own [version-1 record-check contract](CONTRACTS.md#verify---json-schema-version-1); it is not a generic external-report importer or proof of downloaded bytes/code safety. |
| Snyk and other skill/MCP scanners | The README has a Snyk Advisor badge and an opt-in executable seam; neither supplies an already-retained, artifact-bound scanner report for this decision. No Snyk/Cisco/NVIDIA execution, account access or provider evaluation occurred. Lack of a supplied report is not a claim that these tools cannot export one. |

E6 (`mcpm report --json`) and E10a (`mcpm policy check`) remain
[roadmap proposals](ROADMAP-ADOPTION.md#wave-2--enterprise-unblockers-self-serve-still-zero-backend), not
shipped report contracts. The command registration in `src/commands/index.ts`
has neither command. `mcpm audit --sarif` is an existing outbound SARIF mapper;
`MCPM_EXTERNAL_SCANNER` is a separate opt-in execution seam. Reusing their
existence as proof that retained-report ingestion already exists would be wrong.

## One real report, inspected without an adapter

The Scorecard artifact provides an actual candidate rather than manufactured
fixtures. Its API metadata and local bytes agree:

- Artifact ID `13495384588`, `scorecard-results`, 16,201 ZIP bytes; created
  `2026-11-06T10:51:05Z`, expiry `2026-11-11T10:51:04Z`, not expired at retrieval.
- ZIP SHA-256
  `3a846afa5dc1bc73b7d3542133a6945be155fffcf5b95ff898551f76bb660b0b`
  matches the artifact API digest; workflow metadata names source `288f71f...`.
  This associates the retained ZIP with that workflow/head; it is not independent
  proof of the scanner's analyzed tree or each check's coverage.
- Single `results.sarif` member, 71,602 bytes, SHA-256
  `9cf4740b2d10d968dd7e7293e840a6f23aea46a662786c369c28f0dd6df48692`.
  Read bounded bytes without filesystem extraction or report-command execution.
- SARIF 2.1.0; driver `Scorecard` semantic version `v5.6.0`. The action is pinned
  to `fa7117db83c52d787ae5a89f350999701505d78e` (v2.5.0). Automation IDs reference
  Scorecard source `61e84743356275f6ffca23b1b2f2cb945e19eb96`, **not mcpm's source**.
- Three runs: branch-protection 0 results/1 rule, local 1/11, online-scm 2/6.
  None contains `invocations`, `versionControlProvenance` or an artifact digest
  inventory. Rule counts and empty arrays do not establish complete analysis.
  The report alone cannot bind a particular npm tarball or #156 snapshot pair.

The raw report already presents these three findings for maintainer review:

| Finding | Bounded interpretation from report/source; no automatic disposition |
| --- | --- |
| `PinnedDependenciesID`, score 9 | Points to `scripts/dogfood-release.sh:60`, the variable install target. That script supports both a newly packed archive and a published spec. The static finding alone cannot distinguish those selected bytes or certify their dependency closure. |
| `CodeReviewID`, score 0 | Provider assertion: 0/30 approved changesets under Scorecard's human-review criterion. Its embedded rule documentation explicitly excludes AI reviews. The recorded Sol/Astra review process does not refute this result or become human approval. The 30 underlying approvals were not independently rechecked. |
| `CIIBestPracticesID`, score 0 | Provider assertion: no detected OpenSSF Best Practices badge; badge status was not independently rechecked. Retain the posture signal rather than classify it as malicious artifact content or a false positive. No badge-provider account was accessed. |

This bounded manual triage could make those dispositions directly from the
original report, embedded criteria and current source. It identified no decision
that required a new mcpm importer; no finding was silently dismissed or fixed.
That supports using the existing report/native views and API envelope for this
consumer now, without claiming an adapter could never help. The source-confirmed
pinning limit and two unverified provider assertions are not a binary labeled
true/false-positive corpus. A warmed repeat timing attempt failed its
cross-process monotonic check; no reviewer-minute or efficiency claim is made.

The actual CodeQL SARIF was also inspected: version 2.27.4,
`versionControlProvenance.revisionId` equals the full main SHA above, and its
three artifact paths have no member hashes. All six results are
`js/bad-code-sanitization`, two each in `scripts/native-client/approval.mjs`,
`consent-vscode.mjs` and `trust-vscode.mjs`; none has a per-result `baselineState`
or `suppressions` entry. This is source-bound evidence, not proof of downloaded
release bytes, complete analysis or six confirmed vulnerabilities. Vulnerability
triage/fixes are outside this adapter decision.

Existing labeled fixtures do not repair the comparison gap: the #156 tests
assert archive/declaration/coverage outcomes, and the guard's legitimate corpus
labels MCP message behavior. Neither is ground truth for Scorecard repository
posture or CodeQL source analysis. No external scanner report on those same
artifact fixtures was supplied, and producing one would require a separately
scoped execution evaluation. Additional true-positive counts, false-positive
rates and baseline-versus-adapter review cost therefore remain unmeasured;
reformatting the existing findings would not establish incremental findings.

## Binding, coverage and privacy gate

The inspected candidate supplies real bytes and a pinned tool version. It still
needs external run metadata for mcpm source identity, an explicit analysis-mode/
coverage interpretation, and a demonstrated consumer outcome requiring ingestion.
Missing embedded fields do not make import impossible: a pinned, validated local
envelope could retain external bindings and explicit unknowns. That contract and
its useful outcome must be selected before implementation, rather than treating
every unknown as clean or building an envelope merely to create demand. The
workflow retains its downloadable artifact for five days; copying it to a
temporary local directory does not create a durable retention policy. The SARIF
contains source paths, snippets and messages. Its checksum authenticates neither
publisher nor redaction; no general secret-redaction guarantee was established.
Do not publish arbitrary future raw reports or give their assertions native
trust-floor credit merely because this public report was readable.

Reopen one adapter only when the maintainer can supply all of these:

1. A named merge/release/review decision or workflow problem and evidence that
   ingestion adds useful findings or improves review over the existing Security
   tab, original report and release receipts. It need not block a release.
2. One already-produced report, exact producer/schema revision, retained original
   bytes/digest, and verifiable binding to the analyzed source/archive members.
   Source SHA, artifact hash, tool source and runtime version remain distinct.
3. A defined mode/phase/resource coverage contract: unknown versions, stale/wrong
   subjects, truncation, skipped/error/unavailable/provider-dependent phases must
   remain refused or incomplete. A green workflow or no findings cannot fill gaps.
4. An explicit local redaction/access/retention policy, including original-report
   handling, expiry/deletion and what may enter a shareable receipt. Withheld
   content remains a coverage gap; hashing is not secret redaction.
5. A labeled same-input comparison against the current workflow, recording
   incremental actionable findings, false positives/abstentions and reviewer
   minutes, including preparation/binding work. Agree the useful outcome and
   review-cost budget before evaluating it; do not infer benefit from format reuse.

Until then #157 stays deferred/unbuilt. No adapter framework, automatic scanner,
new provider access, runtime score/policy change, package version or release is
justified by this decision. #140 and the remaining queue require their own gates.

Temporary evidence: `/private/tmp/mcpm-157-scorecard-evidence/` contains the original
ZIP/SARIF, CodeQL SARIF, artifact and hosted-analysis metadata, exact-head check
metadata, release-asset metadata and the bounded triage receipt (including failed
timing). This directory is temporary and not an OSS report store.
