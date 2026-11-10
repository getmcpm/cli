# Trust assessment and supply-chain evidence

The trust score is a 0-100 assessment based on publicly available metadata. It is
**not** a source code audit.

What it checks:

| Component | Points | What it measures |
|---|---|---|
| Health check | 0-30 | Reserved startup/response check; current commands do not run it and score 15/30 |
| Static scan | 0-40 | Regex-based detection of hardcoded secrets, prompt injection patterns in registry descriptions/arguments, typosquatting in package names, suspicious argument schemas |
| External scanner | 0-20 | Results from a third-party scanner you have installed, opt-in via `MCPM_EXTERNAL_SCANNER` (off by default) |
| Registry metadata | 0-10 | Active registry status and publication age; capped to 0 when critical or high findings are present. The reserved download-count input is not populated by current commands |

The score's `isVerifiedPublisher` input currently comes from the registry's
`status === "active"` flag. That credit does not independently verify publisher
identity. The scorer supports download-count credit, but product registry reads
supply no download count, so that credit is unavailable.

Levels are a **ratio** of the points available, not absolute: **safe** at 80% of
`maxPossible` or better, **caution** at 50-79%, **risky** below 50%. With no external
scanner (`maxPossible` 80) that puts safe at 64 points, not 80.

`mcpm audit` displays **`clean · not run`** when its measured scan buckets have
no findings and satisfy the clean-label predicate, but the health check did not run.
That display label does not change the numeric score or stored `level`. The `safe`
level is a score-ratio classification, not proof that a health check ran; an opt-in
external scanner can raise the ratio into that band despite the unrun health bucket.

Audit does not apply the release-age cooldown used by `why`, `install`, `up` and
`lock`, so the same candidate's scores can differ. Read performed/unrun checks and
findings alongside the number rather than treating different commands as identical
assessments.

Without an external scanner, `maxPossible` is 80: the external bucket is dropped from
the denominator rather than counted as a failure. That denominator is not the achievable
ceiling of current commands. Search/info report a global `maxAchievableScore` of 62/80;
npm launchers top out at 60/80. See [agent evidence](AGENT-WORKFLOW.md) for
performed/unrun checks. The static scan catches common patterns but cannot detect all
vulnerabilities. Treat the score as a signal, not a guarantee.

**External scanning is opt-in and mcpm never downloads a scanner.** Set
`MCPM_EXTERNAL_SCANNER` to the path or name of a scanner you have already installed.
mcpm probes it with `<scanner> --version` and, if that exits 0, scans each server with
`<scanner> --json <server-name>`, expecting `{"findings": [...]}` on stdout. A scanner
whose output cannot be read is treated as **absent** rather than as a clean pass, so the
bucket leaves the total instead of silently earning 20/20 — otherwise any binary that
exits 0 would raise trust scores.

Package runners (`npx`, `uvx`, `pipx`, `docker`, shells, …) are refused, including via
symlink or a runner's `-cli.js` entrypoint. Be clear about what that is worth: it is a
**footgun guard**, not a security boundary. Anyone who can set this variable can usually
set `PATH` or drop a file too. What it buys is that a pasted `npx …` recipe — or a
future mcpm default drifting back toward one — cannot quietly re-create the
fetch-and-execute vector this seam was rebuilt to remove.

The retained scanner assessment explains why no scanner is enabled by default: the
evaluated `snyk/agent-scan` accepted a bare registry coordinate as input, but converted
that coordinate into an `npx`/`uvx`/`docker run` invocation and started the server to
inspect it live — conflicting with mcpm's install-then-verify design at the two call
sites (install, lock) where this runs before you've committed to installing — and
required a Snyk account and `SNYK_TOKEN`, with no offline mode. This is the repository's
dated scanner assessment, not a current survey of all providers; see [the implementation
rationale](../src/scanner/tier2.ts).

Those 20 points **inform the score but cannot clear a safety floor.** The MCP server
surface (`mcpm_install`, `mcpm_up`, `mcpm_setup`) enforces a hard trust floor of 25 that
no caller-supplied value may lower — and since `MCPM_EXTERNAL_SCANNER` names an
arbitrary executable, a two-line script printing `{"findings": []}` is caller-supplied
input too. So the floor is compared against mcpm's own evidence only: health check +
static scan + registry metadata, out of 80. The exclusion is one-directional — a scanner
reporting a critical finding still drags a server *down* through the floor (via the
registry-metadata cap), it just can't push one up through it. Your own `--min-trust`
threshold, a stack file's `policy.minTrustScore`, and `mcpm audit --fix` are unaffected:
there the same person picks both the threshold and the scanner. `audit --fix` is also
the one score gate that *deletes* rather than refuses, so subtracting the bucket there
would remove more servers, not fewer.

## Locks and provenance

`mcpm verify` is a repo-only, **client-free** gate: it checks your committed
`mcpm-lock.yaml` against npm's **published** `dist.integrity` record and exits non-zero
on integrity drift, an unverifiable record, a format mismatch, or a suspicious missing
baseline. Because it needs no AI clients installed, it runs on a hosted CI runner (where
`mcpm up` cannot).

It also checks that the lock **covers** what `mcpm.yaml` declares. The other gates read
only the lock, so they pass over a lock that is missing servers — the coverage check is
what stops a truncated lock from verifying green while enforcing less than you asked
for. A lock holding no servers at all never passes unless an `mcpm.yaml` beside it
confirms nothing was declared. Correspondingly, `mcpm lock` is all-or-nothing: if any
server fails to resolve it reports every failure and writes **nothing**, leaving the
previous lock intact.

It **also re-verifies Sigstore provenance** for every npm server whose lock recorded a
cryptographically `verified` baseline: it re-runs the offline crypto verification
against npm's current record and fails closed if the attestation regressed — the signer
identity changed, it no longer verifies, or it can't be re-checked. This is
evidence-gated, so a lock with no `verified` baselines (the common case) is unaffected.
`mcpm up --frozen` runs the same integrity + provenance freeze before installing.

`mcpm lock` also records each npm server's **published provenance identity** (the source
repo + immutable GitHub repo/owner ids behind the build) and WARNs when it drifts across
versions — a repo/owner change or a signed→unsigned drop, the shape of a
hijacked-publish (Postmark) attack.

`mcpm lock` and `mcpm why` additionally **cryptographically verify** the provenance
**offline** — the attestation's Sigstore bundle is checked against a vendored trust root
(the cryptographic step is offline; fetching npm records still uses the network), and the attested subject digest is bound to the package's
`dist.integrity`, so a valid attestation for a *different* tarball can't pass. When it
holds, the record reads `verified`; otherwise `attested` — an *unverified* registry
record — or `unsigned` (neutral). Report-only, and honest about scope: `verified` means
the **build identity** is cryptographically attested by the CI's OIDC token — **not**
that the code is safe (a same-repo CI compromise mints a valid attestation).

The record checks compare published registry metadata; mcpm does not intercept the
package bytes that npx/uvx download at launch. See [contracts](CONTRACTS.md) for
coverage, [usage](USAGE.md#stacks-and-ci) for setup and the
[Action](../.github/actions/mcpm-verify/README.md) for separate Action-source and
executed-CLI pins.
