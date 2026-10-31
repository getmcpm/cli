# Structured doctor evidence validation

Unreleased candidate, measured 2026-10-31 (Asia/Hong_Kong).

## Outcome and boundary

`mcpm_doctor` now exposes the existing DoctorModel, already schemaVersion 1, through
an advertised `outputSchema` and `structuredContent`. JSON text uses the same
model and formatting. The tool keeps zero arguments and read-only annotations;
there is no second summary, synthetic health score, new dependency or provider call.
[The contract](CONTRACTS.md#doctor-evidence-unreleased) defines the consumer workflow.

The baseline wire regressions failed for both modern and legacy peers: output
schema/structured evidence was missing, and mocked access denial was converted
to a missing config with a successful result. The minimal shared-helper fix returns
missing only for ENOENT/ENOTDIR and propagates other failures. Adapter read failures
retain existing malformed/issue semantics. This also changes uncertain config
existence failures in CLI doctor; it does not redesign the DoctorModel.

## Source and transport checks

Linked real SDK transports validate modern 2026-07-28 and legacy 2025-11-25. Tests
assert declared version1 output, unchanged JSON/structured values, explicit absent
clients, nullable crossClient, malformed files, skipped entries, missing runtimes,
conflicts and unreadable drift, and secret findings without the synthetic value.
Access denial returns a tool error without structured success evidence. Schema
checks reject unknown versions/missing evidence and preserve additive fields.

## Packed candidate sandbox

```sh
pnpm build
pnpm pack --pack-destination /tmp
bash scripts/dogfood-protocol.sh /tmp/doctor-evidence /tmp/getmcpm-cli-0.15.0.tgz
```

The version is the repository placeholder, not a publication claim. The existing
wrapper binds archive SRI, every runtime JavaScript file, raw dependency lock,
harness hashes and copied public usage skill. Runtime is Linux/arm64, Node 26.11.1,
offline UID1000/read-only root/cap-drop/no-new-privileges/no host bind mounts;
only disposable synthetic state is available. Installation happens during image
build with scripts disabled. No host client files or credentials are supplied.

Twelve doctor comparisons use SDK 1.32.1 legacy, SDK 2.3.1 auto and pinned-modern
clients against the candidate's actual SDK 2.4.0 dual-era server. Each is compared
directly and through guard. Empty and malformed configs, skipped invalid entries,
conflicting client definitions, unavailable uvx and value-free secret findings are
observed through real adapters. A chmod 000 directory causes actual EACCES under
UID1000; restoring access must allow another successful doctor call. Error paths
name separate disposable profiles, so only those generated path segments are
normalized for comparison; exported wire receipts remain raw.

Reviewed candidate: 87 passes, zero failures, two expected unsupported reference
combinations, four exclusions; twelve doctor comparisons augment the existing 75.
Temporary evidence: `/private/tmp/mcpm-structured-doctor/reviewed-candidate`. Astra reviewed implementation, harness and docs and found no actionable defect;
no review fixes were necessary. Its focused checks passed 56 source tests and 10
harness checks. The final parent run passes 3,661 source tests, 91.11% line and 86.49%
branch coverage, typecheck/build, the negative coverage gate and 11 total harness/
launcher checks. The freshly built candidate and unchanged fixed reference were
rerun after review. The fixed reference passed 40 comparisons, zero failures and
two expected unsupported combinations. Independent checks verified every runtime
JavaScript hash, archive SRI, raw dependency lock and harness hashes, and the actual
offline container boundary for both receipts.

## Limits

Missing configs and unavailable unused runtimes can coexist with ok:true; advisory
cross-client drift and secrets do not affect it. A null comparison is not clean
consistency. Malformed also groups read/adapter failures, not only JSON syntax.
Secret finding values are omitted, but arbitrary server names or diagnostic text
are not a general public-report redaction. Fatal operations yield no success
contract, not an empty clean model. Diagnostic strings are not stable error codes.

These are named SDK stdio clients and synthetic config operations, not installed
editor UI, host activation, a real provider/model, launch/liveness or universal
MCP conformance proof. The fixed CLI 0.47.0 reference matrix stays independent;
production dependencies and both root/reference lockfiles are unchanged.
