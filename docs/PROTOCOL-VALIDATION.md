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
CI runs this command on Ubuntu and uploads the evidence even when comparisons
fail. This job tests the released baseline, independently of the source tests.
It does **not** test a candidate runtime change or automatically follow `latest`.
The isolated manifest's `npm test` is the container entry point; use the wrapper
above on the host. Host-only launcher regression checks run with
`node --test scripts/protocol-sandbox/launcher-check.mjs`.

## Reproducible inputs and isolation

`scripts/protocol-sandbox/package-lock.json` freezes the complete test-only
dependency tree. The initial inputs are CLI **0.47.0**, SDK v1 **1.32.1**, SDK v2
client/server **2.3.1**, Inspector **2.10.1**, and Node **26.11.1** on Debian
Bookworm. The Docker base is pinned by its multi-platform manifest digest.
Production dependencies and the root lockfile are unchanged. To update a peer
or release baseline, change its exact version in the isolated package manifest,
regenerate that lockfile with npm, rerun the matrix, and update the measured scope
here. Do not infer compatibility from the package's major version alone.

Only the harness and existing public `modern-*.json` fixtures enter the Docker
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
120-second deadline. On timeout the launcher kills the attach process and stops
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

Installed native clients and their configuration-adapter lifecycles, model/skill
behavior, HTTP/OAuth, and universal protocol conformance remain **not tested**.
This matrix does not cover every method, extension, subscription or repeated
MRTR depth; it does not claim complete schema validation or detection coverage.
It neither upgrades `mcpm serve` nor translates protocols in the guard.

Next, use a disposable macOS VM with synthetic settings to validate VS Code and
Claude Code, including real harmless tool calls and the user-global files mcpm
actually manages. Isolated-profile connection tests alone do not establish
adapter compatibility. Expand to other clients/platforms only with named
versions and observed results; test-account access may be needed for real agent
tool invocation.
