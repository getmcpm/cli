# #140 retained Skills fixture verification — 2026-11-08

**Scope: the existing release harness consumes retained Skills evidence.** The
maintainer uses its actual candidate/published-archive compatibility results to
accept or reject release evidence. The original #140 MVP asks for pinned Beta
fixtures; it does not require a new public CLI or native host. Metadata inspection
remains the separately shipped v0.48.1 behavior. The harness adds full retained
fixture consistency checks without changing production guard decisions.

## Pinned interpretation

Authoritative [Beta specification](https://github.com/modelcontextprotocol/ext-skills/blob/649f7aee87d631ac4d1fdd3b12eef0c6264fdb3a/specification/beta/skills.mdx):
commit `649f7aee87d631ac4d1fdd3b12eef0c6264fdb3a`, blob
`9c71c420d846efd963c084039f1ff1c5ce66bf11`, 55,458 bytes, SHA-256
`6e33a33762783a02dc4c13c889dda5b8d7c525649012cf77da12d80c04ce6851`.

The specification targets modern `2026-07-28`. The legacy `2025-11-25` cases
measure SDK transport interoperability separately. Identity includes the trusted
originating connection and full URI; server names and URI schemes are not origin
authentication. Static resources describe raw-byte digest/size relationships.
Dynamic content cannot inherit that binding. Changed resources or frontmatter
need fresh verification. Host approval/loading and publisher identity are
separate, unmeasured properties. The specification's 512-resource/16-MiB envelope
is a minimum host-support requirement, with larger hosts permitted, rather than
a universal invalidity threshold.

## Retained inputs and independent oracle

The helper and its tests live in `scripts/protocol-sandbox/`. The actual candidate
SDK serves four declared members: the real public mcpm skill, a UTF-8 reference
with BOM/CRLF/multibyte bytes, a binary asset and a nested supporting SKILL.md.
The trusted `skills-oracle.json` maps each scenario and initial/read/refreshed
state to exact inert fixture files. Expected outcomes and connection labels come
from the harness. The verifier imports no peer generation or peer hashing logic.

Each direct/guarded receipt retains the full observed wire plus
`value.capture`: schema/spec/protocol revision, originating connection label,
selected URI, held request ID, read IDs and optional refresh/directory/list IDs.
Responses bind to their actual requests and causal windows. Missing, truncated,
ambiguous or errored evidence cannot be replaced by expected fixture bytes.

`value.verification` records the selected identity, held/refreshed sets, observed
transitions, successfully decoded resources' byte length/SHA-256/oracle hash,
coverage gaps and wire/oracle bindings. SHA-256 covers decoded resource bytes, not JSON serialization
or normalized text. UTF-8 preserves BOM, CRLF and multibyte data; malformed Unicode
and noncanonical base64 are rejected. Text captures cannot prove arbitrary
original encodings. Malformed/errored observations retain explicit gaps without
fabricated decoded-byte fields. Frontmatter is parsed independently of the SDK and compared
to the held and refreshed entries, including fields beyond name/description.

Each connection keeps its own wire hash. Valid concurrent response reordering
can change that hash while preserving semantic results. Pair comparison checks
semantics and oracle identity without rewriting either retained capture.

## Coverage and the release gate

| Check | Required observed outcome |
| --- | --- |
| Complete static set and origin identity | Every declared member matches both its held digest/size and independent source bytes. Same-name/same-URI origins stay separate; origin substitution fails even with identical bytes. |
| Held versus current state | Rotated/added/removed/digest/size/frontmatter changes, dynamic refresh and failed refresh cannot inherit current aggregate consistency. Previously verified reads remain historical observations. Order-only refresh is benign only when the entry remains consistent. |
| Missing, extra or corrupt reads | Missing/unread/error resources remain incomplete. Unlisted/changed/wrong-URI content, malformed encodings or frontmatter cannot become consistent. |
| Listings and directories | A complete selected get can be checked while catalog coverage is unknown. Partial listing cannot establish absence or a globally clean catalog; contradictory selected entries are retained transitions. Directory coverage names the exact requested subtree; a newly discovered unlisted child cannot redefine the held set. |
| Capture/profile boundaries | Unknown contracts, missing/duplicate/unordered observations, unsupported URI interpretations and profile excess remain nonclean. A valid declared set cannot prove no server-unadvertised files exist. |

The candidate adds 26 scenarios in each protocol era, each exercised directly
and through the actual guard. SDK-rejected bad entries/reads remain actual RPC
errors and incomplete evidence. Invalid forms the SDK cannot emit are tested by
explicit local retained-capture mutations, not described as SDK observations.
Negative self-checks corrupt digests, omit members, swap origins, lose refreshes,
misorder events and relabel outcomes; assertions must reject the fabricated clean
result. Positive concurrent reordering remains valid.

A harness case passes only when the observed verification status matches its
fixed expected status. An expected mismatch/incomplete/changed/invalid case is
not counted as clean skill verification. `declaredSetComplete` describes only
the selected observed declared set. Catalog/directory scope and unadvertised-file
unknowns remain separate. The existing 32 Skills metadata comparisons and fixed
published-reference pins are retained.

## Validation and consumer decision

Merged in [PR #333](https://github.com/getmcpm/cli/pull/333), main `58d6727`, after
all nine CI checks. Hosted CI capture/runtime bindings were independently replayed
in addition to the local evidence below. No npm release was required.

Source checks passed typecheck/build and 3,846 tests (three skipped). Fifty-nine
local Node harness/self-checks passed, including 48 retained Skills self-checks
and the launcher check; the container passed the other 58 checks. Astra
independently reviewed and reproduced false-consistency paths involving
catalog transitions, scoped URI coverage, causal/role accounting, lost refreshes
and fabricated aggregate counts. Sol fixed them with regression checks; the final
negative controls reject those cases.

Both final attempt-3 matrices passed **139 comparisons, zero failures, two
expected unsupported combinations and four exclusions**. Each includes the
existing 87 comparisons plus 52 retained Skills case pairs. Their verification
outcomes are 12 consistent, 16 incomplete, 14 mismatch, eight changed and two
invalid; a passing negative case remains nonclean. Parent and Astra independently
replayed each artifact's 104 direct/guarded captures and 412 decoded reads against
the fixed source-file oracle and retained wire hashes. They also checked every
member of the reports claiming complete declared-set coverage.

| Supplied artifact | SHA-256 | Final dependency-lock SHA-256 |
| --- | --- | --- |
| Fresh local 0.15.0 placeholder archive | `9a39064a617c76b843e9241b8324a3fc7e09842bc986dce0760b696e7a4805e4` | `de92120742892d61ba365aadb2f2abf8c1a2e2a1928d5036da08507230a4f6d0` |
| Actual published 0.51.0 archive | `48ce5dc69fcb5dd7dbf876772a26cfc6c8964edbc79585d02028a79bc48c7aef` | `952b03691b93c82ee8cff6de51111cffe9436af03a7ff34b5f61bd3e28cbb3cd` |

The actual published bytes were freshly checked against npm SRI and match the
previously authenticated [v0.51.0 release](RELEASE-2026-11-06-v0.51.0.md).
This evaluation does not claim a fresh Sigstore authentication. All 66 runtime
JavaScript files matched independent builds and installed-image readback for
the appropriate archive/version; the placeholder build is not substituted for
published bytes. The wrapper calls either explicit-archive run `candidate` mode.
Actual Skills peers use SDK 2.4.0; fixed 2.3.1 peers and legacy 1.32.1 remain pinned.

Independent image readback matched archive/runtime, lock, harness/oracle/fixture
hashes and the actual network-none, read-only UID1000/capabilities-zero/no-host-bind/
no-new-privileges boundary. Execution and readback containers were removed.
The maintainer consumed the expected/observed outcomes plus independent bindings
and **accepted the bounded fixture compatibility evidence**. This completes the
fixture-scoped MVP; it does not mean all tested skills were clean or that the
production guard verifies manifests. Package runtime and public usage-skill
bytes are unchanged; no npm release or companion repin is needed.

Final temporary evidence:

- `/private/tmp/mcpm-140-{candidate,published}-protocol-attempt3-20261108/`
- `/private/tmp/mcpm-140-parent-replay/{candidate,published}-attempt3.json`
- `/private/tmp/mcpm-140-parent-replay/{candidate,published}-attempt3-readback/verified-binding.json`
- `/private/tmp/mcpm-140-parent-replay/maintainer-decision-attempt3.json`
- `/private/tmp/mcpm-140-astra-final-bindings.json`
- `/private/tmp/mcpm-140-phase3-green-20261108.log`
- `/private/tmp/mcpm-140-source-validation-summary-20261108.json` (observed tool-result summary, not a raw stdout log)

Transport freeze SHA-256:
`a0cb44a4f3c24b3acd32842d8b923c34d64c7e6bd9a2c8b95f1277c240ce1ff6`.
Earlier attempts 1/2 retain their own pre-fix checker identities and are not
attributed to the final checker. The withdrawn planning draft is preserved
separately in `/private/tmp/mcpm-140-withdrawn-defer-20261107/`.

The harness binds actual archive/SRI/runtime files, dependency lock, SDK version,
pinned specification, helper/peer/oracle/fixture hashes and retained wire. Its
existing offline container boundary remains required. No provider/model, native
client, real client configuration or credential-store access is added. No new
public CLI, cache, approval grant, automatic fetching or runtime safety score is
implemented. Original public-skill distribution remains a reviewed local directory.
