# Cursor MCP lifecycle validation

The Cursor adapter writes the user-global `~/.cursor/mcp.json` file. This
bounded harness checks that the real Cursor Agent CLI can discover an
`mcpm`-managed stdio server through that file while `mcpm` changes its
lifecycle state. It uses the repository's synthetic registry double and
native MCP peer. Child processes receive a minimal environment, a fresh
`HOME`, an empty working directory, and Cursor's file credential-store setting;
the harness does not copy an existing profile or pass provider credentials.

## Reproduce

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
below for that isolation. The report covers seven cases:

1. install and discover;
2. guard-enable and discover through the relay;
3. update to the fixture's `2.0.0` publication and discover;
4. guard-disable and discover again;
5. check whether the client-level disable flag blocks discovery;
6. client-level enable clears the flag and permits discovery; and
7. remove prevents discovery while retaining an unrelated config entry.

Each discovery must contain `initialize`, `notifications/initialized`, and
`tools/list` on a fresh peer and must contain no `tools/call`. The initialize
response must report the expected fixture version, including `2.0.0` after
update. Disabled and removed discovery use the same server name. Removal
must produce no new peer traffic. If disabled discovery still succeeds, the
report records a `limitation`, sets its overall status to `partial`, and exits
with status 1 after completing the remaining cases. The report is
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

## Observed limitation

The pinned Linux arm64 Cursor Agent CLI `2026.10.22-27dcf5f` ignores the
generic `disabled: true` config flag written by `mcpm disable` for
`mcp list-tools`: it still starts the fixture
and completes discovery. This is a CLI discovery result; editor behavior is
untested. The bounded run therefore reports six passes and one limitation,
not full disable/enable lifecycle compatibility. Do not treat `mcpm disable`
as verified prevention of Cursor CLI server launch.
