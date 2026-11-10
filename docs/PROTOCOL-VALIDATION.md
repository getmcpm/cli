# Sandboxed stdio compatibility validation

Repository test tooling added in v0.47.1. The reference baseline deliberately
remains published v0.47.0; a release does not silently repin the matrix.

Run the pinned **published** CLI against official SDK reference peers, both
directly and through `mcpm guard run --inner`:

```sh
bash scripts/dogfood-protocol.sh /tmp/mcpm-protocol-evidence
```

Requires Docker and a host Node.js to enforce the outer execution deadline.
Provisioning the image needs registry access; the test container has no network.
This default invocation tests the fixed released baseline; it does **not** test
a candidate runtime change or automatically follow `latest`. CI runs it on Ubuntu
and separately builds/packs the current checkout, supplying that archive as the
wrapper's second argument for candidate validation. The upload step runs even
after failure and retains whichever evidence directories were produced; a failed
baseline step skips the later candidate step. See [candidate reproduction and
coverage](SERVE-PROTOCOL-VALIDATION.md#reproduce).

The isolated manifest's `npm test` is the container entry point; use the wrapper
above on the host. Host-only launcher regression checks run with
`node --test scripts/protocol-sandbox/launcher-check.mjs`.

## Reproducible inputs and isolation

`scripts/protocol-sandbox/package-lock.json` freezes the complete test-only
dependency tree. The initial inputs are CLI **0.47.0**, SDK v1 **1.32.1**, SDK v2
client/server **2.3.1**, Inspector **2.10.1**, and Node **26.11.1** on Debian
Bookworm. The Docker base is pinned by its multi-platform manifest digest.
That initial fixture addition left production dependencies and the root lockfile
unchanged. To update a peer
or release baseline, change its exact version in the isolated package manifest,
regenerate that lockfile with npm, rerun the matrix, and update the measured scope
here. Do not infer compatibility from the package's major version alone.

Only the harness, the public `skills/mcpm/SKILL.md` usage skill, and existing
public `modern-*.json` fixtures enter the Docker
build context. No host home, client configuration, credentials, SSH agent, Docker
socket, or host directory is mounted. Dependencies install with scripts disabled.
At execution the container uses UID 1000, a read-only root, no network, no Linux
capabilities, no privilege escalation, and limits of 768 MiB, two CPUs and 128
processes. Each comparison has separate synthetic state in a disposable tmpfs.
A fresh anonymous Docker volume holds evidence; cleanup removes both it and the
container after exporting files. The built image remains cached locally.

The harness verifies its UID, effective capabilities, addressed network
interfaces, read-only application directory and absence of host paths/sockets.
The exported container configuration records the actual network/mount/resource
settings. Requests and child shutdowns have deadlines; the outer test run has a
180-second deadline. On timeout the launcher kills the attach process and stops
the container before exporting evidence. Raw wire captures have message/byte
budgets; SDK captures are limited by the tmpfs and checked against a 1 MiB budget
when read. Large raw messages are represented by size/hash instead of full wire
text. Everything is
public or synthetic. These checks are evidence of this container boundary, not a
claim that containers resist a kernel exploit.

## Measured matrix

Initial local run on **2026-10-10**, Docker Desktop Linux/arm64: **40 pass, zero
fail, two expected unsupported combinations**, from **42 direct/guarded
comparisons**, plus four explicit excluded scope categories. Seven harness
self-checks cover comparison failures, recovery contents, unsupported-error
correlation, invalid JSON-RPC envelopes, out-of-order correlation, silent/closed
peers, and unterminated output. A host launcher regression covers successful,
failed and timed-out runs, stop-before-export, cleanup and stale-evidence refusal.
CI separately supplies Linux runner evidence.

| Cases | Observations |
| --- | --- |
| SDK v1 → v1; v2 auto → v1; v1 → v2 dual-era; v2 pinned → v2 | Ordinary tools/resources/prompts and concurrent tool calls; observed legacy `2025-11-25` or modern `2026-07-28`, with matched opening messages and declaration pins. |
| Interactive calls for all four pairs | Deterministic sampling, elicitation and roots callbacks. Modern retry carries four keyed responses, a fresh id, unchanged arguments and exact opaque state. SDK v2's legacy shim is exercised too. |
| Modern decline/cancel, progress, timeout and abort | Expected callback outcomes, progress delivery and successful calls after cancellation/timeouts. |
| Tool-output and server-input attacks | Correlated block errors and subsequent recovery. Legacy input blocks return to the server's request id; modern input blocks return to the client and do not trigger the input callbacks. |
| Legacy client → modern-only server | **Unsupported**: observed `-32022`, preserved through the guard. |
| Modern pinned client → legacy server | **Unsupported**: discovery returns `-32601`; the SDK reports failed era negotiation without fallback. |
| SDK v1 and v2 auto → `mcpm serve` | Legacy initialization/fallback and actual tool listing only; no registry/model API calls. |
| Eleven existing modern public fixtures | Benign payload identity, intended blocks and explicit unsupported-shape warnings. |
| Raw shapes and policies | 512 nested arrays, a 100 KB result, unknown version `-32022`, discovery drift across restart without repinning, coverage-warning ignore/block overrides. |
| Malformed/oversize/closed/silent peers | Bounded rejection; malformed frame block and `frame-too-large` event; silence reaches a deadline. |
| Inspector CLI → SDK v2 | Actual tool listing through an explicit server configuration, directly and guarded. No Inspector web proxy is started. |

SDK/Inspector agreement is not an independent conformance oracle: these tools
share upstream code. Additional assertions check observed version metadata,
result discriminators, error codes, request ids, retry arguments/state, callback
counts, cancellation forwarding, persisted pins/events and benign/recovery
contents. The relevant requirements are
the [versioning contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
and [MRTR contract](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr).

## Dependency refresh — 2026-11-06

Inspector is now pinned to **2.11.0** after a deliberate fixture update; the
published CLI **0.47.0**, SDK v1 **1.32.1**, SDK v2 client/server **2.3.1** and
container image stay fixed. The isolated lock also updates qs **6.17.1**,
fast-uri **3.1.9**, body-parser **2.4.0**, undici **8.12.3**, ip-address **10.7.5**
and zod **4.6.7**. No expected protocol outcomes were weakened or changed.
The fixed published baseline again passed **40 comparisons**, with **zero failures**,
**two expected unsupported combinations** and **four exclusions** on Linux/arm64.
The packed updated placeholder-version candidate separately passed **87 comparisons**,
with **zero failures**, the same **two unsupported combinations** and **four exclusions**.
Its archive SHA-256 is `398a2f267fa49b21c5d3fe6d4087c24d63d24ae5a75d01e86eb701cbeaa82fb8`;
this proves that candidate, not a published release.

The root dependency refresh separately resolves prompts **8.7.5**, SDK v1
**1.32.2**, hono **4.13.16**, @hono/node-server **2.1.6**, and qs **6.17.1**.
A clean lock regeneration also advances Sigstore bundle **5.0.1**, Sigstore verify
**4.1.3**, semver **7.8.6**, and Vitest/coverage **5.1.0** within existing ranges.
Build/test tooling now uses tsup **9.0.0** and Vite **8.3.5**. All nine root
overrides remain present and the root lock has no fixture importers.

The [tsup 9 release](https://github.com/egoist/tsup/releases/tag/v9.0.0) raises
its Node floor; the [Vite 8 migration](https://vite.dev/guide/migration) changes
its transformation toolchain. Their published engine ranges, and every installed
package engine declaration, accept the CLI's Node **22.22.2**, **24.15.0** and
**26.0.0** floors. The existing build and test configuration needed no migration.
On Node **24.20.0** with pnpm **10.30.0**, frozen install, typecheck, build,
**3,761 tests**, coverage gates, the coverage-threshold probe, and **45 native/
protocol harness self-checks** passed. Production, full-root and isolated-fixture
dependency audits reported zero advisories. Native harness self-checks are not a
fresh native-client VM run.

## Reading the evidence

`report.json` records package versions, npm artifact URL/integrity, lockfile,
CLI entrypoint and harness hashes, OS/architecture/Node, boundary checks,
per-case outcomes and counts. Each successful comparison links separate direct
and guarded files containing observed protocol, synthetic wire data where
applicable, stderr, pins and events. Assertion failures retain links to observations
already captured. `container.json` and `image.json` identify the executed settings
and image. `execution.json` records the overall run status and exit code, including
deadline failures (124), which may leave a partial `report.json`. Failed assertions
produce `fail` and a nonzero exit; unsupported outcomes require the expected client
error and a correlated protocol rejection. The launcher requires an empty output
directory so older files cannot be mistaken for new evidence. The JSON schema is
local harness output, not a public CLI contract.

## Remaining verification

The separate [native client harness](NATIVE-CLIENT-VALIDATION.md) exercises named
VS Code/Claude Code builds and their actual global adapters in disposable macOS
VMs, using synthetic dependencies. Other native clients/platforms, model/skill
behavior, HTTP/OAuth, and universal protocol conformance remain **not tested**.
This matrix does not cover every method, extension, subscription or repeated
MRTR depth; it does not claim complete schema validation or detection coverage.
The fixed published baseline does not establish modern `mcpm serve` support
and does not translate protocols in the guard. The separately identified
[candidate serve suite](SERVE-PROTOCOL-VALIDATION.md) now tests modern and legacy
serve calls without changing this historical reference baseline.

Native results are separate from this reference-peer matrix. Isolated-profile
connection tests alone do not establish adapter compatibility. Expand to other
clients/platforms only with named versions and observed results; real provider
or agent behavior may need dedicated test-account access.


## Skills carrier candidate checks (v0.48.1)

The explicit candidate-archive mode additionally resolves the candidate's actual
SDK server dependency to serve the Skills extension, without changing the fixed
2.3.1 reference peers or 0.47.0 baseline. It copies the repository usage skill into
memory and applies separate metadata/body/directory poison variants. The copied
skill is included in `harnessSha256`. See [Skills guard validation](SKILLS-GUARD-VALIDATION.md)
for the named comparisons and security limits. These calls test transport and
guard decisions; they do not activate a skill in a host or measure agent behavior.


## Retained Skills fixture checks (#140)

The retained-fixture MVP extends the release-harness consumer with 26 retained
Skills scenarios per protocol era, directly and through the actual guard.
Trusted connection identity, correlated held/read/refreshed captures and every
declared member's raw bytes are checked against the pinned Beta interpretation
and independent fixture files. Expected nonclean outcomes must remain nonclean;
the harness passing such a case is not a clean skill verdict. Both final local
candidate and actual 0.51.0 archive matrices passed 139 comparisons with zero
failures; independent replay/readback and maintainer acceptance are recorded in the
[contract, oracle and validation record](RETAINED-SKILLS-DECISION.md).

No public CLI or production guard manifest enforcement is added. Native loading,
approval, publisher authenticity and whole-server hidden-file coverage remain
outside this fixture validation. Legacy SDK interoperability is separate from
the Beta specification's modern protocol requirement.

## Doctor evidence candidate checks (v0.49.0)

The explicit candidate-archive mode adds twelve doctor comparisons: missing,
malformed, mixed issues/skipped entries/advisory drift/secrets, and actual access
denial followed by recovery, across the v1 legacy client, v2 auto-negotiated client
and v2 pinned-modern client. The container supplies synthetic configs only. Schema
advertisement, text/structured identity, unknown coverage and error separation are
asserted independently of SDK validation. Fixed reference inputs remain unchanged.
See [doctor validation](DOCTOR-EVIDENCE-VALIDATION.md).


## Published v0.50.0 checkpoint — 2026-11-06

The integrity/provenance-verified npm v0.50.0 archive passed 87 modern/legacy direct/guarded comparisons, zero failures, two expected unsupported combinations and four exclusions. Independent read-back verified the complete runtime JavaScript set, raw lock, harness/public skill and actual offline container isolation. Fixed published reference pins remain unchanged. See [publication and companion evidence](RELEASE-2026-11-06-v0.50.0.md) for hashes, CI/deployment state and limits. Historical candidate receipts above retain their original attribution.
