# Native MCP client smoke tests

Repository tooling added in v0.47.2. Its reproducible published mcpm baseline
remains 0.47.1; a release does not silently repin the native measurements.

This repository harness exercises installed VS Code and Claude Code inside
separate disposable macOS VM clones. It uses the actual user-global configuration
paths written by mcpm, records real native MCP traffic and invokes harmless tools.
The test inputs, registry metadata, package launcher and model responses are
synthetic. No host account, keychain, client profile or provider key is imported.

## Reproduce

Use an Apple Silicon Mac with a compatible macOS virtualization environment,
enough memory for a 6 GiB guest, and space for the pinned image/cache. The image
download is about 27 GB compressed. The measured host was macOS 27.2/arm64 with
32 GiB RAM; the guest is macOS 26.6.2/arm64. Tart 2.40.1 is required. Obtain it
from its [official release](https://github.com/openai/tart/releases/tag/2.40.1)
and verify the SHA-256 in `scripts/native-client/pins.json`; the tested app is
signed by Cirrus Labs, Inc. (`9M2P8L4D89`). Follow Tart's vendor license.

```sh
node scripts/native-client/prepare.mjs /tmp/mcpm-native-payload
node scripts/native-client/run-vm.mjs /path/to/tart \
  /tmp/mcpm-native-vms /tmp/mcpm-native-payload /tmp/mcpm-native-evidence
```

Use a fresh evidence directory and a separate task-owned VM storage directory.
The runner refuses existing VM storage without its ownership marker. A prepared
payload may be reused only with matching pins. Provisioning downloads public
artifacts; native execution is offline except for guest loopback communication.

The private npm manifest/lockfile pins published mcpm 0.47.1 and Claude Code
2.1.296, including transitive dependencies. VS Code 1.141.0 (commit
`2a59476c9bfcb90b3ddc372c36762471b7dfad1c`), Node 26.11.1, Tart and the public
Cirrus macOS image are pinned by version/digest. The preparation step verifies
archive hashes and installs npm dependencies with lifecycle scripts disabled.
Claude Code's reviewed, pinned native-binary installer runs inside the offline
guest to connect its preloaded platform binary to the CLI entry point.

### Test a candidate with realistic configuration

Build and pack the current checkout, then explicitly prepare/run that artifact:

```sh
mkdir -p /tmp/mcpm-candidate
pnpm build
pnpm pack --pack-destination /tmp/mcpm-candidate
node scripts/native-client/prepare.mjs /tmp/mcpm-candidate-payload /tmp/mcpm-candidate/getmcpm-cli-0.15.0.tgz
node scripts/native-client/run-vm.mjs /path/to/tart \
  /tmp/mcpm-native-vms /tmp/mcpm-candidate-payload /tmp/mcpm-candidate-evidence \
  --candidate --realistic-config
```

The source package uses placeholder version 0.15.0; that candidate is not the
published 0.15.0 release. `cliArtifact.kind`, archive SHA-256/SHA-512, lock integrity
and installed file hashes identify it. Candidate mode verifies that the package
manifest and complete `dist` file set/bytes match the archive (including lazy
chunks, missing files and extra files), and that guest/host identities agree. It
does not establish source provenance; record the source revision/diff used for
the fresh build separately. The default published baseline and pins are unchanged.
Candidate preparation freezes its own dependency lock with scripts disabled.

The realistic suite adds comments/trailing commas and input declarations to VS
Code's actual user-global file. Ordinary declared environment values use client
variable references, including quotes/backslashes; VS Code also resolves a known
synthetic input prompt. Claude Code exercises environment/default references in
its user-global file. Echo replies must contain the exact resolved values before
and after wrapping/update. Raw backup bytes, input declarations and unrelated
comments/settings must survive the lifecycle. All eight/seven baseline case
requirements still apply. The helper accepts only the named fixture prompt with
its exact prefilled synthetic value; account/sign-in prompts remain excluded.

VS Code parsing uses Microsoft's `jsonc-parser`, checks every parse error and
rejects duplicate server containers/names before edits. Only the managed entry
is edited; removal can retain a legal trailing comma. Other clients continue
to use strict JSON. This does not migrate configuration scopes or resolve
variables inside mcpm.

Current [VS Code documentation](https://code.visualstudio.com/docs/agent-customization/mcp-servers)
prefers portable `.mcp.json`/Copilot global locations and distinguishes Agent Host
routing. This harness still measures the adapter's user-profile `mcp.json` through
the native Tool API. Portable/workspace paths, alternate profiles and Agent Host
chat routing remain separate, unverified integration paths.

Reviewed and independently repeated local measurements on 2026-10-12 passed
**8/8 VS Code and 7/7 Claude Code** in both the realistic candidate suite and the
unchanged published-baseline mode. These use macOS 26.6.2/arm64 and the named
client versions below. Host/guest hashes, all 134 candidate distribution files,
raw configuration/backups, actual variable bindings, correlated cancellation,
post-removal receipts and cleanup were checked. All 3,588 source tests,
typecheck/build and 13 harness self-checks passed. Astra fixed inherited-key
server removal, incomplete candidate chunk identity and a pre-wire cancellation
fixture race; cancellation now waits for the current slow request before firing.
The managed server entry can be reformatted; comments/settings outside it and
the original raw backup are preserved.

## Boundary and fixture scope

### Default consent suite (Phase 2C)

Run the separate approval suite with the same prepared payload and a fresh
evidence directory:

```sh
node scripts/native-client/run-vm.mjs /path/to/tart \
  /tmp/mcpm-native-vms /tmp/mcpm-native-payload /tmp/mcpm-consent-evidence \
  --approvals
```

Add `--candidate` when using a freshly packed candidate payload. `--approvals`
and `--realistic-config` are separate suites. The default baseline and existing
lifecycle cases retain their original behavior and pins.

The consent suite disables VS Code global auto-approval and uses native Tool
API confirmation dialogs. An exact echo grant is made through the normal
**Manage Tool Approval** UI at profile scope. It does not edit the approval
database. Inline chat and Agent Host permission flows remain separate.

Claude Code runs its interactive terminal UI with `--permission-mode default`,
without print mode, permission bypass flags, or seeded tool grants. The guest's
built-in Expect provides a real 120×40 PTY; the driver records raw output and
the current rendered screen, including Unicode, cursor movement and erasure.
Only the exact synthetic fixture choices are selected. Workspace trust and
the synthetic loopback API-key prompt are recorded separately. The native
client writes its exact-tool grant to local settings; the harness only reads it.
The Messages gateway supplies deterministic responses without a live provider.

| Case | Required observation |
| --- | --- |
| One-shot re-prompts | Two different echo arguments in one client session each require visible approval, dispatch once and return the exact value from the same peer PID. |
| Deny and Escape | Refuse and cancel separately at the visible permission prompt; neither dispatches a tool call. Initialization/discovery traffic is allowed. |
| Persistent exact-tool grant | Grant echo through the client UI, restart the client with a new nonce and peer PID, and call echo without another prompt. An ungranted warn tool still prompts and is denied. |
| Guard after approval | Approve the attack fixture through the native UI, observe the peer call and guard block, then recover with the previously approved echo. |

Consent decisions must precede dispatch. Missing/repeated decisions, mismatched
arguments, unexpected grants, timeout kills, reused observations and incomplete
case reports fail validation. Negative Claude decisions can stop the turn
without returning a tool result to the gateway. They require a usable native
prompt and orderly exit, rather than an invented denial response.

Native Phase 2C measurements are pending. Mock PTY and harness self-checks do
not establish installed-client compatibility.

The runner clones the immutable image independently for **VS Code first, then
Claude Code**, using the base image's synthetic `admin` account. Each clone is
stopped/deleted after its client completes, fails, or the runner receives
SIGINT/SIGTERM. An interrupted run fails and does not start the next client.
The image cache remains for repeat runs. Reclaim it by removing only the
task-owned storage after checking
that no VM is running; never use personal VM storage for these tests.

The VM has no host filesystem shares, clipboard, audio or USB sharing. It uses
host-only networking and a guest PF deny-all rule with loopback excluded. Only
the whitelisted public client/runtime payload and fixture code cross the guest
control channel. Evidence returns as bounded, validated JSON filenames/data;
the host does not extract a guest-controlled archive. The public payload is
capped at 1 GiB/50,000 entries and rejects escaping
symlinks before copying. Evidence is limited to 32 files, 4 MiB per file and
16 MiB total. CPU/memory limits, the guest VirtualMac model, actual mounts,
enabled PF status and exact deny-all filter rules are checked and recorded.
This tests the declared boundary; it does not establish resistance to a
hypervisor or kernel exploit.

The public CLI runs `install`, `guard enable`, `update`, `guard disable` and
`remove`. A marked Node test loader supplies two fixture registry/package
versions, and a narrowly scoped launcher runs the dependency-free peer. This
allows actual native configuration changes and a 1.0.0 → 2.0.0 update while
offline. It does not measure the live registry, package downloading or supply
chain verification. The committed Phase 1 harness remains separately pinned to
its published 0.47.0 baseline.

VS Code runs the packaged application with a development fixture extension.
The extension opens and verifies the actual user-global MCP document, activates
native collections, and uses `vscode.lm.invokeTool`. Native consent dialogs for
the known fixture are accepted in the guest UI. The helper excludes sign-in and
account dialogs and does not edit VS Code's approval database. Fixture global
auto approval is confined to the disposable guest. A window reload tests actual
MCP reconnect with a changed peer PID, rather than accepting a cached result.

Claude Code runs its real CLI against the global `~/.claude.json` entries. A
loopback Messages API fixture supplies deterministic tool-use rounds and records
the native tool results. The API key is a synthetic test string. No real provider,
subscription usage or model generation occurs. Known fixture tools are
preapproved; interactive chat and normal per-tool consent workflows are outside
this smoke suite.

## Named cases and evidence

Reviewed local measurement on 2026-10-11: **8/8 VS Code and 7/7 Claude Code cases
passed** on macOS 26.6.2/arm64 with Node 26.11.1. Actual native traffic identifies
VS Code using legacy `2025-11-25` and Claude Code using modern `2026-07-28`.
This result does not imply every protocol mode supported by either product
has been exercised.
The eleven account/VM-free self-checks and existing 3,569 source tests passed;
typecheck/build passed. Native raw evidence is local and may expire; the result
summary is also recorded in the project's Obsidian validation note. Review
found that an earlier nominal pass accepted a timed-out VS Code drift attempt;
that result is superseded. The corrected run requires and observed normal
VS Code completion for drift. A separate interrupted VM run verifies cleanup.

| Case | Required observation |
| --- | --- |
| Install and echo | mcpm writes the actual global file; native opening identifies the client and a real tool call returns the exact nonce/version/marker. |
| Enable, block and recovery | The app loads the wrapped launcher; attack content produces the guard block message, then an echo succeeds. Declaration/tool pins contain real hashes. |
| Warn and forward | The existing Unicode-warning fixture arrives unchanged and the guard records its expected warning signature. |
| Cancel and recover | VS Code waits up to 10 seconds for its current slow call to reach the peer, then forwards correlated cancellation and continues. Claude Code is deliberately interrupted during a real slow call; a new invocation succeeds. A deadline or cancellation before the wire call cannot count as success. |
| VS Code reload | A real window reload reestablishes MCP; the repeated echo has a different peer PID. |
| Update | The public CLI updates the fixture package coordinate while retaining the guard, extra arguments, environment and unrelated configuration. The native tool reports 2.0.0. |
| Schema drift | Changed tool schema is blocked, no call reaches the peer, pins remain unchanged, and the attempt finishes without a deadline kill. Reverting the fixture restores a successful native call. |
| Disable and remove | Unwrapping restores the updated original launcher and forwards direct attack text. Removing the fixture preserves unrelated settings and the native client observes its absence. |

The matrix contains eight VS Code cases and seven Claude Code cases. The runner
requires every named case, matching runtime/client versions and matching fixture
hashes, and rejects empty/incomplete success reports or missing/reused
observations. Per-case JSON records include execution status/deadlines, client receipts, synthetic wire
traffic, configuration, pins and events from that invocation. Each observation
has a unique filename linked from its case; recovery calls cannot overwrite
earlier evidence. The final removal observation includes raw configuration and
backup bytes; Claude Code also exports its `mcp get` not-found receipt.
`manifest.json` identifies pins, flags, VM configuration,
all guest fixture/extension hashes, host harness hashes and cleanup.
Read failures and unexpected client behavior are
failures; they are not silently classified as unsupported.

Run the account/VM-free harness self-checks with:

```sh
node --test scripts/native-client/self-check.mjs
```

CI runs these checks on Node 22/24/26. CI does not run the macOS VMs; native
measurements are local, named-version evidence. Logs contain only synthetic test
data, but may include product-generated prompts and diagnostics. Keep raw
evidence local; publish scoped results rather than entire client transcripts.

## Remaining verification

Live providers and actual model/usage-skill behavior, interactive chat/default
approval workflows, other clients/platforms, additional configuration variants,
and complete protocol conformance remain unverified. Native client versions
and observed wire protocol must be recorded rather than inferred from package
versions. Updating pins requires repeating the native matrix. SIGKILL, host
shutdown and hypervisor crashes cannot guarantee cleanup; inspect the task-owned storage
before reclaiming any leftover clone.

The next step is real model/skill evaluation with dedicated, authorized test
access and bounded usage, followed by additional named clients/platforms.
