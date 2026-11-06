# Artifact-review candidate evidence — 2026-11-06

This record describes project backlog #156 before merge/publication. Current
published CLI remains v0.50.1; no v0.51.0 publication is claimed here. The
[command/profile contract](ARTIFACT-REVIEW.md) defines the supported archive and
declaration subset. Source checks, historical and final candidate execution, and
the real consumer decision below have separate identities. The 0.51.0 changelog
section is prepared for release; this does not assert publication.

## Reviewed source checkpoint

Implementation base: `1b573fc3568c42dcb1a08149da05eb3c702f32b3`. Sol implemented
the command; Astra independently reproduced and fixed archive/declaration,
reference, pointer and coverage edge cases, then reproduced a Markdown parsing
CPU regression and replaced the backtracking scan with a bounded linear scan.
The latest source receipt is
`/private/tmp/mcpm-156-astra-source-freeze-v2-20261106.json`.

That source checkpoint records Node 24.20.0 typecheck (main/tooling), build,
62 focused tests, whitespace checks and all 163 test files passing: **3,846 tests
passed, three skipped**. It supersedes the first Astra source freeze. These are
source results; fresh packed-candidate execution is recorded separately below. The
placeholder package version remains `0.15.0`; no dependency/lockfile or override
change is part of #156. Documentation additions after the source freeze are
tracked separately and do not change runtime bytes.

## Final latest-source candidate

The fresh candidate archive is
`/private/tmp/mcpm-156-final-candidate-20261106/getmcpm-cli-0.15.0.tgz`, SHA-256
`9a39064a617c76b843e9241b8324a3fc7e09842bc986dce0760b696e7a4805e4`.
Its consumer binding receipt names the latest Astra source-freeze SHA-256
`aa42dbbe48d0e16ee73e29e32f007121e4cfd46a6a33bfc18bc936438f3b8b25`.
The actual isolated image identity is
`sha256:c32866659f49450a1e74f6e7dd13a06670b36a3f2068e01ccbfe5fd3352392a6`.

Independent read-back matched all **66 installed JavaScript files**, the three
input archive hashes below, and every reported member hash, size and mode.
Both newly executed consumer reports matched the previously reviewed reports:
31 old-to-capture and eight tag-to-capture changed/unknown records, with exit 1
and both coverage flags false. The maintainer's retain-source/no-rollback
decision was reaffirmed; no global mutation, native activation or safety
approval followed. The isolated execution used UID 1000, no network, a
read-only root and no host bind mounts. Home/project directories were checked
empty after execution, not traced for absence of transient writes. The temporary
read-back container was removed after its evidence was retained.

| Check | Final candidate/source result | Local receipt |
| --- | --- | --- |
| Clean installation and public CLI smoke | Passed against the exact candidate archive | `/private/tmp/mcpm-156-final-smoke.log` |
| Modern/legacy direct/guarded stdio protocol | 87 passed, zero failures, two expected unsupported combinations, four exclusions; independent actual-image/runtime/input binding passed | `/private/tmp/mcpm-156-final-protocol-20261106/{report,verified-binding}.json` |
| Real macOS confinement dogfood | Passed control access, denied synthetic-secret read, intact relay, tamper refusal and event logging | `/private/tmp/mcpm-156-final-confine.log` |
| Source coverage | Passed: 90.15% statements, 86.64% branches, 87.20% functions, 91.92% lines | Maintainer coverage run |
| Negative coverage-threshold probe | Passed; failing thresholds were rejected | `/private/tmp/mcpm-156-final-negative.log` |
| Real consumer and member/runtime binding | Passed receipt bindings; both product reports intentionally incomplete, retention reaffirmed | `/private/tmp/mcpm-156-final-candidate-20261106/consumer/run-final/verified-binding.json` |

These are candidate/static/protocol/confinement observations for their named
surfaces. They do not prove native artifact loading, default approvals, provider
behavior, universal host coverage or a published package. Published-byte
authentication and companion synchronization remain release gates.

## Historical real-consumer inputs

The maintainer prepared inert uncompressed USTAR snapshots outside the product.
The separate preparation record names the two upstream commits and the explicit
captured source root; the mcpm receipt itself authenticates neither provenance
nor host cache/activation state. Preparation normalized owner/time and retained
member content/modes. Only `.git` metadata was omitted from the captured source;
no vendor or `node_modules` directory was present or omitted. An earlier generic
omission description was corrected while preserving the original record and
unchanged archive bytes.

| Snapshot | Regular files | Archive SHA-256 |
| --- | --- | --- |
| Ponytail tag 5.3.2, upstream commit `16352ac229eb08a9598dcae48fe9f2b342567d86` | 213 | `fead09d7275d23ca5713e92873ec4ab10cf1fa177090b4bb5d18d3e1f929e10f` |
| Ponytail tag 5.3.3, upstream commit `7801d061243d7b753bad0e0b3c057cd250b11755` | 214 | `032b3aa5083a19bec10a8539b9033fdb6f4b5f61a606204073129ae3eb67c544` |
| Explicit local 5.3.3 source capture | 216 | `3ab7882f3a3251aa890c78e095258b52a5dd2715635ed74415855e4a37c35bb2` |

Inputs, preparation script/proof and consumer decision are retained temporarily
under `/private/tmp/mcpm-156-consumer-v2-20261106/`. Both comparisons used
`--profile claude-plugin-2026-11-06 --withhold .git --json`.

## Historical candidate execution and decision

The earlier candidate npm archive SHA-256 was
`0456b014efb655a4037c3127c7579010d4399711b2a911f3b9942df9e26717e5`, bound to the
first Astra source-freeze receipt SHA-256
`ed7d58f54b9549911253b3c0cdd12429f127a2889f0378827dc6ba34757f7c1c`.
This **predates the latest Markdown CPU fix**. The `run-v2` directory name below
identifies a consumer-run revision, not the newer source-freeze v2.
The first `run-v1` consumer attempt failed on input-file permissions before
producing reports and is excluded. Its receipt is retained. The original CPU
regression and source-capture metadata-pack limit failure are also excluded from
passing evidence; no failed capture archive was produced. The final candidate
above was freshly executed after the fixes.

Retained container inspection and binding receipts matched that archive, all
66 installed JavaScript files and the three input hashes. The execution used
UID 1000, no network, read-only root, dropped capabilities, no-new-privileges
and no host bind mounts/credentials. Home/project directories were checked empty
after execution; this is not a syscall-level assertion that no write occurred.
No artifact hooks/scripts, native validators, installers or provider/model calls
were executed.

| Comparison | Result | Evidence used by the maintainer |
| --- | --- | --- |
| 5.3.2 tag → captured 5.3.3 source | Exit 1; byte and declaration coverage incomplete; 31 changed/unknown records | Changed executable/source files, declared shared-hook source/timeouts, literal references and explicit coverage gaps |
| 5.3.3 tag → captured 5.3.3 source | Exit 1; byte and declaration coverage incomplete; eight changed/unknown records | 208 matching known content/mode pairs; five README/translation modifications, two SVG unknown additions, one withheld `.env.example` |

Dynamic `node -e`, opaque Claude-band modules, unsupported manifest fields and
nine other-host manifests remained interpretation gaps. The default-withheld
`.env.example` member and prepackaging `.git` omission remained byte-coverage
gaps. Archive buffering still read packaged member bytes; hashing was not
redaction. Other-host declarations, including Codex, were not evaluated as loaded
components. Configured/cached/loaded/enforced host states remained unknown.

The actual maintainer decision was to **retain the reviewed 5.3.3 source update
without requesting a rollback**. No global changes or native install/activation
approval followed. Manual semantic review separately checked hook timeout
5→15 seconds, activation subprocess timeout 1→3 seconds, Git-list buffer
1→64 MiB with the existing line-count cap, and the opaque band's transcript
lookup across Claude project folders. SVG XML was inspected separately; the
receipt's file-role heuristic did not establish executable status or safety.

The one-consumer gate is met for this bounded experiment: the receipt combined
captured byte/mode identity with component/reference/coverage mapping instead of
requiring that inventory to be assembled manually. Public-tag diff alone did not
bind the captured local bytes. This is not a measured time saving, evidence of
general demand, superiority over native/Git/APM workflows, or a safety verdict.

Historical local receipts:

- `/private/tmp/mcpm-156-consumer-sandbox-20261106/run-v2/{consumer,old-to-cache,tag-to-cache,verified-binding}.json`
- `/private/tmp/mcpm-156-consumer-v2-20261106/consumer-decision.json`
- `/private/tmp/mcpm-156-consumer-v2-20261106/preparation-proof.json`

## Remaining delivery gates

The latest-source repack, consumer bindings, smoke, protocol, confinement and
coverage and negative-threshold checks are complete as described above.
Final artifact/documentation review, hosted checks,
merge, publication, published-byte authentication and companion synchronization
remain pending in this record. The prepared 0.51.0 changelog section is not
publication evidence. The one-consumer result does not authorize #157/#158 or another host
dialect; those retain their own scope and evidence gates.
