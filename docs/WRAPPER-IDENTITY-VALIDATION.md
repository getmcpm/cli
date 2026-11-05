# Wrapper recognition validation — 2026-11-05

#155 merged in [PR #312](https://github.com/getmcpm/cli/pull/312) as
`d895575b80671a95c987a440323606ca21543687`, included in v0.49.2 release preparation.
The candidate checks below are distinct from publication/archive verification.

## Behavior and compatibility

A server could supply `guard run --inner` among its ordinary runtime arguments
and be counted as already guarded. The install-to-enable regression now enrolls
that plain server. Recognition distinguishes plain, recognized and ambiguous
entries using launcher position, marker structure and the original-entry hash.

Direct `mcpm` launchers (including Windows command spellings) and Node invocations
of an existing metadata-backed `@getmcpm/cli` dist bin are supported. Tests cover
the shared metadata-backed package layout used by npm/npx/global/development
installs, plus symlinks, older Node paths,
malformed/duplicate flags, missing hashes/paths, settings preservation and refusal.
Node paths are classified without executing them; an older Node may still fail
at runtime. A moved arbitrary alias cannot reveal its former identity.

Ambiguous wrapper-shaped entries are not counted guarded. Status/doctor surface
repair guidance, and enable/disable/update refuse to silently replace them.
Restore a trusted original config before re-enrollment. Doctor uses its existing
malformed-config issue; no new public evidence schema is introduced. Plain
publisher-controlled marker lookalikes remain enrollable. Static recognition
cannot authenticate a replaced mcpm binary or forged local package metadata.

## Review and source checks

Sol implemented the fix and meaningful failing-before regressions. Astra reviewed
all callers and fixed a malformed symlink-prefix case that still became plain
when `--inner` was missing. Astra also removed newly build-dependent fixtures,
preserved plain malformed-entry repair and made status classify each entry once.
Final checks: **3,734 tests passed, three skipped**, typecheck/build and diff check
passed. All 44 existing native/protocol harness self-checks also passed.
No remaining actionable Astra findings in the reviewed scope.

## Packed protocol sandbox

The exact packed candidate passed **87 comparisons, zero failures, two expected
unsupported reference combinations and four exclusions**, through modern and
legacy SDK peers, direct and guarded. Independent read-back checked archive SRI,
all runtime JavaScript files against the build, raw dependency lock, harness and
public skill hashes, and the actual offline UID1000/read-only/no-capabilities/
no-host-bind container boundary. Reproduce the existing SDK suite with:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm pack --pack-destination /tmp
bash scripts/dogfood-protocol.sh /tmp/wrapper-proof /tmp/getmcpm-cli-0.15.0.tgz
```

Candidate archive SHA-256:
`971402d091f6810e36c6c32b60d5d232e534d8bffc5e721012ae49fcb6511ad3`.
The 0.15.0 version is the repository placeholder, not a publication.

## Native launcher observation

Pinned **Claude Code 2.1.296**, Linux/arm64 with Node 26.11.1, ran in a separate
disposable container with the reviewed archive installed. A synthetic user-global
`.claude.json` pointed to the existing harmless native peer with marker-looking
arguments. Real mcpm enable changed the entry, native `claude mcp list` reported
Connected, and peer wire recorded discovery. Disable restored the original entry,
including its arguments and synthetic environment. Unrelated config survived.

The container was offline, UID1000, read-only root, cap-drop ALL and
no-new-privileges, with no host bind mounts. Only task-owned disposable state was
available. Native package dependencies used the existing pinned native-client
lock; installation ran during image preparation. The existing pinned Claude
native installer connected the platform binary. No real credentials were used.
Evidence and probe are retained locally in `/private/tmp/mcpm-155-native`,
`/private/tmp/mcpm-155-native-evidence` and `/private/tmp/mcpm-155-protocol`.
The native test container and its volume were removed after evidence read-back.

This is a fresh Linux launcher/discovery round trip, not a native tool invocation,
provider/model call, permission enforcement or macOS/Windows client measurement.
Existing VS Code/Claude macOS native evidence retains its original versions.
Neither this result nor static recognition establishes binary authenticity,
universal protocol conformance or immunity to local package replacement.
