# Skills-over-MCP guard validation

Released v0.48.1. Candidate measurements from
2026-10-31 (Asia/Hong_Kong) remain distinct from published-artifact evidence.

## Contract and scope

The [stable Skills extension](https://skills.extensions.modelcontextprotocol.io/specification/stable/skills)
defines `skills/list`, `skills/get`, ordinary `resources/read` and optional
`resources/directory/read`. Skill entries expose verbatim frontmatter before a
host reads content. The [TypeScript SDK Skills API](https://ts.sdk.modelcontextprotocol.io/v2/servers/skills)
provides the fixture seam; its `attach` wiring is experimental.

Four source regressions reproduced metadata frames returning `pass` before the
change: Skills description, nested frontmatter, resource description and resource
title. One new `discovery_metadata` carrier scans list/get frontmatter and `_meta`,
and resource listing name/title/description/annotations/`_meta`. It reuses the
existing metadata injection patterns, Unicode concealment and traversal budget.
Critical findings block; explicit local policy overrides remain effective.

Responses carry no request method. Resource directory and ordinary resource
listing replies share `result.resources`, so both are scanned, including alternate
URI schemes. Opaque resource URIs, cursors, manifests and digests are not treated
as instructions. File text remains the existing retrieved-data carrier: by default, warn and
forward unchanged when an injection pattern matches. Explicit local overrides can
raise a resource signature to block or suppress a finding. Findings identify a heuristic
pattern, not malicious intent; legitimate instructions containing `<important>`
or `<system>` can trigger the inherited metadata patterns.

## Reproduction

Build and pack the candidate, then use the existing container wrapper:

```sh
pnpm build
pnpm pack --pack-destination /tmp
bash scripts/dogfood-protocol.sh /tmp/skills-evidence /tmp/getmcpm-cli-0.15.0.tgz
```

The tracked version is a repository placeholder; publication injects a tag version.
The wrapper verifies the candidate archive SRI and every built runtime JavaScript
hash. The receipt records dependency versions, raw dependency-lock hash, harness
hashes (including the copied public usage skill), actual wire observations, events,
state and the container boundary. It uses an offline UID1000 Linux container with
read-only root, dropped capabilities, no-new-privileges, no host bind mounts and
only disposable state. Installation happens during image build with scripts off.

The existing pinned CLI0.47.0, SDK1.32.1 and client/server2.3.1 reference matrix is
unchanged. Skills fixtures resolve the packed candidate's actual SDK2.4 server
rather than silently upgrading those peers. `SkillsExtension.load(memorySkillFiles)`
serves the repository usage skill with benign, poisoned frontmatter and poisoned
body variants. A separate valid SDK `SkillSource` supplies poisoned directory
metadata: the SDK's default file listing has no description and correctly passes.

Thirty-two direct/guarded comparisons cover four variants × four methods ×
modern `2026-07-28` and legacy `2025-11-25`. Metadata poisoning blocks list/get;
directory poisoning blocks directory discovery; poisoned file text is identical
through the guard with resource warnings. Benign values are identical. Each pair
also reads the file after inspection to prove recovery; list/get manifest digests
and sizes are checked against the actual returned bytes as fixture consistency,
not as a guard guarantee.

## Measured evidence

Candidate sandbox: **75 passes, zero failures, two expected unsupported
reference-peer combinations**, four explicit exclusions. Linux arm64 / Node26.11.1;
Skills server SDK 2.4.0. The extra32 comparisons are additional to the existing43
candidate comparisons. Temporary receipts: `/private/tmp/mcpm-skills-guard/reviewed-candidate`.
The same harness against the independently verified published v0.48.0 archive
reproduces exactly six missing blocks: modern/legacy skill list/get and poisoned
directory metadata all reach the client. Its other69 comparisons pass, with the
same two unsupported and four excluded outcomes. These six are intentionally
failed security assertions, not transport failures. Receipt:
`/private/tmp/mcpm-skills-guard/reviewed-released-baseline`.
Astra reviewed the complete implementation and fixed an evidence gap: a later
recovery-read warning could satisfy the original read assertion. The final harness
requires exact ordered action/signature/carrier events, direct poison presence,
exact block identity, and unchanged opening/recovery responses. Negative harness
checks reject missing/relabelled warnings. No runtime defect remained after review.
The reviewed build is validated again, separately from earlier attempts.

The full source suite passes 3,649 tests; line coverage91.07%, branch86.46%.
Typecheck/build, the negative coverage-threshold gate, and ten protocol/launcher
harness self-checks pass. Runtime JavaScript hashes, archive SRI, raw lock and
harness hashes and the actual offline container boundary were independently
verified for the reviewed candidate; the fixed published reference remains
40 passes, zero failures, two expected unsupported combinations.
Initial fixture expectation failures are retained as failed attempts and do not
count toward final proof.

## Limits

No skill install, archive extraction, execution, host activation/consent, real
provider/model or native-editor behavior is tested or implemented. mcpm does not
verify Skills manifests across requests, authenticate publishers from supplied
digests, pin skill approvals, validate every extension shape or detect arbitrary
prompt injection. Binary blobs and external content remain outside this slice.
The SDK also supports these handlers on legacy transports; that measurement is
separate from the stable extension's modern base-protocol requirement. Two
unsupported reference combinations remain legacy→modern-only and modern-pinned→legacy.


## v0.48.1 publication

PR #299 merged as `ae59d9b`, byte-identical to reviewed `d08eb1e`, after all nine
checks passed. Publication and actual-package validation are verified.


v0.48.1 is published and verified. PR #299 merged as `ae59d9b`; release source is `c7082dd735817cb67c0d413172f5d5fb2ce53dbf`. [Publish workflow](https://github.com/getmcpm/cli/actions/runs/41099484146) passed the three package gates and npm publish job. The registry job log records successful publication and cleanup, but GitHub still reports it in progress; job APIs/views also return 502, so final workflow completion remains unconfirmed. npm and the official MCP registry report latest `0.48.1`. Actual tarball integrity, authenticated SLSA source/workflow identity, signed SBOM/tamper rejection and clean-install smoke pass. The exact published archive passes 75 protocol comparisons (including 32 Skills comparisons), zero failures, two expected unsupported reference-peer combinations and four exclusions.

The exact downloaded archive was independently matched to a fresh release-version
build of the tagged source, then run in the same offline Linux/arm64, Node 26.11.1
sandbox with actual SDK 2.4.0. All runtime JavaScript, archive SRI, raw lock and
harness hashes bind the receipt; actual UID1000/read-only/network-none/capability
boundary verified. The explicit-archive harness labels this mode `candidate`; its
input here is the verified published archive. Prior candidate and fixed-reference
measurements remain separate historical evidence. No host activation or real
provider/model/native-editor/HTTP run. Evidence (temporary):
`/private/tmp/mcpm-v0481-release/published-protocol`.
