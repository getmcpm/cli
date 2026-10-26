# Cursor MCP lifecycle validation

The Cursor adapter writes the user-global `~/.cursor/mcp.json` file. This
bounded harness checks that the real Cursor Agent CLI can discover an
`mcpm`-managed stdio server through that file while `mcpm` changes its
lifecycle state. It uses the repository's synthetic registry double and
native MCP peer. Child processes receive a minimal environment, a fresh
`HOME`, an empty working directory, and Cursor's file credential-store setting;
the harness does not copy an existing profile or pass provider credentials.

## Reproduce

The candidate Cursor adapter parks disabled definitions in an mcpm-owned
`_mcpmDisabledServers` map outside active `mcpServers`, in the same file.
Enable restores them atomically. Force replacement, update, guard changes and
removal understand parked entries; none silently reactivates them. Rerun
`mcpm disable` to repair an old active entry with the ineffective `disabled:true`
flag. Ambiguous overlapping names or malformed parking maps are refused.
Unknown fields, unrelated configuration and the original backup are retained.

This affects future discovery, not already-running processes or project-local
definitions shadowing the global entry. A separate native Cursor probe found
that its own disable state is project-scoped under
`~/.cursor/projects/<project>/mcp-disabled.json`; native enable can grant approval.
mcpm does not invoke those commands or edit private approval state. Editor UI
behavior remains unverified.

Build the CLI, obtain a Cursor Agent CLI for a POSIX host, and pass its
executable explicitly. Windows hosts should use the Linux container below.
Use an empty evidence directory; the harness rejects reused directories:

```sh
node_modules/.bin/tsup
CURSOR_AGENT=/path/to/cursor-agent \
  node scripts/cursor-client/run.mjs /tmp/mcpm-cursor-evidence
```

The harness owns the temporary `HOME` and working directory under the evidence
directory. Outputs include a synthetic `~/.cursor/mcp.json`, an `npx` fixture
shim, MCP wire logs, `mcpm` state, Cursor caches, and `report.json`. Native runs
do not enforce a network or filesystem sandbox; use the offline container
below for that isolation. The report covers eight cases:

1. install and discover;
2. guard-enable and discover through the relay;
3. update to the fixture's `2.0.0` publication and discover;
4. guard-disable and discover again;
5. disabled discovery rejects the parked name with no target traffic;
6. an independent active control still discovers tools while the target is disabled;
7. force replacement and guard changes retain disabled state, then enable restores discovery; and
8. remove prevents discovery while retaining an unrelated config entry.

Each discovery must contain `initialize`, `notifications/initialized`, and
`tools/list` on a fresh peer and must contain no `tools/call`. The initialize
response must report the expected fixture version, including `2.0.0` after
update. Disabled and removed discovery use the same server name. Removal
must produce no new target traffic. Disabled discovery succeeding now fails
the suite. Reports hash candidate distribution JavaScript; the source package
version is a placeholder, not a release identifier. The report is
evidence for configuration and discovery compatibility, not a claim that
Cursor can execute a model request without an account.

### Offline Linux container

On a host where the downloaded Cursor artifact cannot run directly, use the
matching Linux container architecture. Mount the checkout read-only, mount a
fresh evidence directory read-write, and disable network access:

```sh
docker run --rm --platform linux/arm64 --network none --read-only \
  --tmpfs /tmp:exec,mode=1777 \
  -v "$PWD":/work:ro \
  -v /tmp/mcpm-cursor-evidence:/evidence:rw \
  -v /path/to/cursor-cli-package:/cursor:ro \
  -e HOME=/evidence/home node:26 \
  node /work/scripts/cursor-client/run.mjs \
    /cursor/dist-package/cursor-agent /evidence
```

Record the Cursor artifact version and SHA-256 beside the evidence. The
container run proves the CLI's stdio MCP discovery path and `mcpm`'s config
lifecycle against a clean home; it does not prove the native Cursor editor,
workspace trust UI, account-authenticated model execution, client approval
prompts, non-stdio transports, or protocol methods outside the exercised
handshake and tool listing.

## Historical limitation (v0.47.6)

The pinned Linux arm64 Cursor Agent CLI `2026.10.22-27dcf5f` ignores the
generic `disabled: true` config flag written by `mcpm disable` for
`mcp list-tools`: it still starts the fixture
and completes discovery. This is a CLI discovery result; editor behavior is
untested. The bounded run therefore reports six passes and one limitation,
not full disable/enable lifecycle compatibility. Do not treat `mcpm disable`
as verified prevention of Cursor CLI server launch.

The candidate replaces that expected limitation with a mandatory no-launch
assertion; it does not repin the historical published reference-peer baseline.

## Reviewed candidate — 2026-10-26

Cursor Agent `2026.10.22-27dcf5f` passes all eight cases on Linux/arm64,
including zero target traffic after disable, a fresh active control, preserved
parking through force replacement/guard changes, and restored discovery on
enable. The candidate report matches all 66 current dist JavaScript hashes.
The unprivileged offline read-only container uses image
`node@sha256:a98e6fda54fdbb22d4238054cca9a2a113bcd1191c09193a535aae22f400aa8e`
(Node 26.12.1). Temporary evidence:
`/private/tmp/mcpm-cursor-gemini/cursor-reviewed/report.json`; actual boundary
settings are recorded in `reviewed-containers.json` beside it.

Astra fixed malformed-root/null-map handling and unrelated sibling preservation.
Source validation passes 3,603 tests (three skipped), typecheck/build and coverage
(91.08% lines, 86.49% branches). The native harness and new peer checks pass
28/28 on Node 24.20.0 with synthetic local-loopback access. Running that existing
suite in the restricted execution sandbox aborts inside Node after partial
checks; that failed attempt is retained separately. No new macOS editor run
or account-authenticated execution was performed. Concurrent configuration
writers retain the existing read/modify/write race limitation.


## Published and verified — v0.47.7 (2026-10-26)

[Release v0.47.7](https://github.com/getmcpm/cli/releases/tag/v0.47.7) includes Cursor disable fix PR #282 (merge `26e2c27`) and release preparation #288, tag source `372c281386de985d9c8d623593dc3ecc8fc04db3`. [Publish run 40362946189](https://github.com/getmcpm/cli/actions/runs/40362946189) passed all five jobs, including Node 22/24/26 clean-package gates and official registry listing. npm latest and the official MCP registry latest both report 0.47.7.

The actual npm tarball matches SHA-512 integrity and the cryptographically verified SLSA subject, exact source commit, GitHub Actions issuer and `publish.yml@refs/tags/v0.47.7` signer. Its signed SBOM verifies and tampering is rejected; the verified tarball passes clean-install release dogfood. Temporary proof: `/private/tmp/mcpm-v0477-release`.

Cursor's eight-pass and Gemini's seven-pass/three-limitation native receipts remain the reviewed candidate measurements. This publication check does not rerun the clients or prove Cursor editor, provider/model, tool execution or OAuth compatibility. Gemini toggle limitations remain open.
