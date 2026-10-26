# Gemini CLI lifecycle validation

The harness uses real `gemini mcp list` against the user-global
`~/.gemini/settings.json` managed by mcpm. Registry responses, package launches,
homes and servers are synthetic. No account, provider key, host profile or
OAuth token is supplied. The native fixture registry and peer are reused;
Gemini internals are not imported as a replacement client.

## Reproduce

Build mcpm, download official `@google/gemini-cli@0.65.0`, verify its SHA-512
against npm metadata, and extract without running installation scripts:

```sh
node_modules/.bin/tsup
node scripts/gemini-client/run.mjs /path/to/package/bundle/gemini.js /tmp/gemini-evidence
node --test scripts/native-client/peer-check.mjs
```

The evidence directory must be empty. Native invocation alone is not a sandbox.
Measured Linux/arm64 runs use an offline, unprivileged container:

```sh
docker run --rm --platform linux/arm64 --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 \
  --memory 1024m --cpus 2 --user 1000:1000 --tmpfs /tmp:exec,mode=1777 \
  -v "$PWD":/work:ro -v /path/to/gemini/package:/gemini:ro \
  -v /tmp/gemini-evidence:/evidence:rw node:26 \
  node /work/scripts/gemini-client/run.mjs /gemini/bundle/gemini.js /evidence
```

Record actual Docker image identity; `node:26` is a mutable example tag. The
measured artifact has npm integrity
`sha512-B+flaYBNqX2zO71I5/gu7ZsnI38NlpOl654HWz+bK8I/P5sGILQsbkTOQ5a9V+w1Q6QO3wf9PlqtuMsl7XxpNQ==`.
This checks artifact integrity, not publisher provenance. The report hashes
candidate dist and extracted Gemini bundle JavaScript and records actual
client version and wire traffic. Source mcpm package version is a placeholder.

## Scope

An untrusted synthetic folder must start no target peer. The harness then
explicitly seeds trust for that disposable folder only and tests install,
guard-enable, update to fixture `2.0.0`, guard-disable, mcpm disable/enable,
native Gemini disable/enable attempts and removal. Unrelated settings and an active
control server must survive.

Connections require a fresh peer PID, initialize/initialized/ping, matching
request/response protocol versions and the expected running fixture version.
The peer now negotiates `2025-06-18` as well as `2025-11-25`; self-checks cover
both and unsupported-version fallback. Existing legacy clients remain supported.

**`gemini mcp list` probes connections, without listing or calling tools.** The
pinned client requests `2025-06-18`. This is not proof of tool execution,
interactive trust/consent UI, model behavior, HTTP/SSE/OAuth, other platforms or
client versions, or full protocol conformance.

## Known limitation

Gemini CLI `0.65.0` warns that mcpm's entry-level `disabled:true` is an
unrecognized key, yet `mcp list` still connects. That case is a limitation and causes overall `partial` status and
exit 1 after other cases finish. Unexpected behavior fails assertions instead
of being counted as an expected limitation.

After mcpm enable clears the unsupported flag, native Gemini disable and enable
both report the listed fixture as not found and exit zero in the pinned client.
The harness matches that refusal exactly and verifies the same target still
connects on fresh peers alongside the control. Both are additional limitations;
exit zero alone is not success. Other failures are not accepted as this known
result. Native enablement integration remains unimplemented. Do not treat
`mcpm disable --client gemini-cli` as launch prevention. Cursor's parking fix
is Cursor-specific. No upstream issue has been filed as part of this work.

The official [Gemini MCP commands](https://geminicli.com/docs/tools/mcp-server/)
and bundled client source guided the fixture. Assertions use observed traffic
and native output. CI runs account-free peer checks; native suites require
separately supplied artifacts and do not repin the published reference matrix.

## Reviewed candidate — 2026-10-26

The final pinned client run completes ten cases: **seven pass, three limitations,
zero unexpected failures**, with `partial` status and exit 1. The limitations
are the ignored/invalid mcpm disabled flag and the native disable/enable
refusals. Successful connections use fresh peers and matching fixture versions;
untrusted-folder refusal and removal produce no new target traffic. The
independent control starts and completes a handshake during native toggle checks.

The report matches all 66 current candidate dist JavaScript hashes. Runtime is
Linux/arm64, Node 26.12.1, pinned image
`node@sha256:a98e6fda54fdbb22d4238054cca9a2a113bcd1191c09193a535aae22f400aa8e`.
Temporary evidence: `/private/tmp/mcpm-cursor-gemini/gemini-reviewed/report.json`,
with actual container isolation settings in `reviewed-containers.json`.
Astra hardened the target-specific disable status and fresh control-wire
assertions. Final source validation and harness-check results are recorded in
the [Cursor candidate record](CURSOR-CLIENT-VALIDATION.md#reviewed-candidate--2026-10-26).
