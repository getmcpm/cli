# Modern and legacy `mcpm serve`

`mcpm serve` uses `@modelcontextprotocol/server` 2.4.0 with the SDK's explicit
`serveStdio(factory, { legacy: "serve" })` entry. Modern `2026-07-28` peers use
`server/discover` and per-request metadata; legacy peers retain initialization.
The same nine tools, full strict input schemas, handlers, trust gates, text
results and declared search/info outputs serve both eras. The guard retains its
v1 SDK framing/types; it does not translate protocols. No HTTP endpoint is added.

## Reproduce

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm build
pnpm pack --out /tmp/mcpm-candidate.tgz
bash scripts/dogfood-protocol.sh /tmp/serve-evidence /tmp/mcpm-candidate.tgz
```

The second argument selects candidate mode and must be a fresh pack of this
checkout's build. Without it, the launcher still runs the committed published
0.47.0 reference baseline. Its package manifest and lockfile remain unchanged.
Candidate mode uses a disposable copy of the reference manifest, replaces only
the CLI coordinate with the local archive, and generates its lock inside the
same pinned build image used for installation. Build installation ignores scripts;
only the later execution container is offline. The report labels candidate vs
published-reference artifacts and records the actual dependency lock.

The archive's SHA-512 must match its installation lock. Every installed candidate
dist JavaScript hash must match the freshly packed source build. Reports record
client/SDK versions, package version (source placeholder), lock/hash identity,
actual observed requests/results and direct/guarded receipts. Source version
`0.15.0` alone is not an artifact identity. The separate serve observer forwards
bytes unchanged and records both disposable SDK discovery probes and calls.

Execution uses Linux, UID 1000, no network, a read-only root, dropped capabilities,
no-new-privileges, capped memory/processes/CPU and disposable writable state.
Only public fixtures, the packed build and harness go into the build context;
no host home, accounts, client profiles, credentials or Docker socket enter it.
Candidate discovery has a bounded three-second probe/five-second connect budget;
the fixed reference mode retains its original budgets.

## Assertions

- Legacy SDK 1.32.1 and modern SDK client 2.3.1 discover all nine strict tools and
  call deterministic `mcpm_list` directly and guarded. Empty synthetic Cursor
  config makes that read-only fixture detectable; no real client is used.
- Modern pinned mode negotiates `2026-07-28` without legacy initialization. Actual
  discovery and `resultType: complete` traffic are required; legacy traffic must
  retain its initialization and negotiated version.
- Unknown modern versions return `-32022`. Extra destructive-tool arguments fail
  validation before handler effects, followed by a successful read-only call.
- The candidate guard retains the reference attack, malformed-frame, oversized
  frame, drift, cancellation, timeout and recovery checks. It does not claim a
  new policy for arbitrary user-supplied names or prompt text.
- In-memory tests use the actual v2 server: legacy clients retain strict schema
  and evidence tests; modern clients verify declared structured outputs and text,
  deterministic listing, unknown-key rejection, and deleted-server install refusal.

CI runs both the unchanged published reference mode and a separate freshly packed
candidate mode, preserving their evidence separately. Initial candidate and final
reviewed results are recorded below; failed attempts remain diagnostic evidence.

## Limits

This proves named stdio operations with synthetic peers and state. It does not
prove all nine tool side effects against live clients, provider/model behavior,
HTTP/SSE/OAuth, Tasks/Skills extensions or universal protocol conformance. The
modern search/info output checks use synthetic registry dependencies. Native
editor compatibility and published-release verification are separate work.

References: [official stdio entry](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio),
[SDK migration](https://ts.sdk.modelcontextprotocol.io/v2/migration/upgrade-to-v2),
[protocol changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog).

## Reviewed candidate — 2026-10-30

The final reviewed build completes **43 passing comparisons, zero failures and
two expected unsupported reference-peer combinations**, with four named excluded
scopes. The separate fixed published baseline repeats **40 passes, zero failures
and the same two unsupported combinations**. Those combinations are legacy to a
modern-only reference server, and modern pinned to a legacy reference server;
the candidate dual-era `mcpm serve` passes both its modern and legacy paths.

Observed runtime: Linux/arm64, Node 26.11.1. The candidate's actual server SDK is
2.4.0; independent reference peers remain SDK 1.32.1 and client/server 2.3.1.
All 66 installed candidate runtime JavaScript hashes, archive SHA-512, raw
exported dependency-lock hash and harness hashes match. Actual container settings
confirm the boundary above. Candidate image identity:
`sha256:24bf324e70bf0399feca9b18d3084671fa703016c632fb577ddf576a7928b18a`.
Temporary receipts: `/private/tmp/mcpm-modern-serve/reviewed-candidate` and
`reference-baseline`; the verified archive is `reviewed-candidate.tgz`.
Temporary paths are not durable artifact storage; CI preserves its own receipts.

Astra reviewed the complete change and fixed false-positive assertions: strict
input rejection must name the unknown key rather than accept any handler/network
error, and deleted-server refusal must identify deletion after a registry read.
A negative harness check rejects unrelated errors. Parent rebuilt and repacked
then independently repeated both sandbox modes after those fixes.

Final source checks: **3,630 tests pass**, line coverage **91.06%**, branch
coverage **86.45%**, typecheck/build and the negative coverage gate pass. Protocol
and launcher self-checks pass **9/9**. Restricted execution timed out in the
existing offline synthetic wheel-launch test; unchanged focused and full checks
pass with the required child-process permissions. Failed initial container and
fixture attempts are retained separately and do not count toward final passes.

## v0.48.0 publication — 2026-10-30

PR #293 merged after all nine hosted checks passed. The merged source matches
reviewed `6777b35`. Publication is verified on npm and the official MCP registry.
The exact downloaded archive passed integrity, authenticated source/workflow
provenance, signed SBOM/tamper checks and clean-install smoke.

The published v0.48.0 archive was independently matched to a fresh build of the
tagged source with its release version injected, then passed the full protocol
sandbox: **43 passes, zero failures, two expected unsupported reference-peer
combinations**. Runtime is Linux/arm64, Node 26.11.1; actual server SDK 2.4.0.
The harness labels its explicit-archive execution mode `candidate`; in this run
that input is the verified published tarball, not a locally substituted package.
Archive SRI, every runtime JavaScript hash, raw lock and harness hashes bind the
receipt. Temporary evidence: `/private/tmp/mcpm-v0480-release/published-protocol`.
The earlier 43-pass candidate and 40-pass reference results remain separate
historical measurements. No fresh native-editor/provider/model or HTTP run.

Release source `4ae38783df7885dbb8d4c4bf1aaf4a75c89cc4f4`; [publication workflow](https://github.com/getmcpm/cli/actions/runs/41021055043).
