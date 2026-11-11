# Coverage-aware audit report

`mcpm audit --report-json` is an opt-in, CLI-only version-1 evidence model for
`~/.mcpm/servers.json`. First shipped in v0.53.0; check help on older installations.
It reads the mcpm store, fetches **latest registry metadata** for accepted names,
and runs the existing static scanner. It does not inventory client configuration,
select effective project entries, assess installed package bytes/versions, or
perform health checks. Existing scores, levels and gates are unchanged.

The report path writes no store, config, backup or lock files, including when the
store is missing. It does not launch MCP servers itself. If
`MCPM_EXTERNAL_SCANNER` is configured, the existing opt-in installed executable
may run (`--version`, then `--json <name>`); mcpm cannot guarantee that arbitrary
executable is non-executing or read-only. It never fetches a scanner. Unset that
variable when external execution is outside the authorized task. Availability is
probed once, only after a registry lookup and static scan succeed.

The fixed source is read as strict UTF-8 JSON, at most 1 MiB, using the existing
bounded reader. The supplied home is canonicalized; symlinks below it, non-files,
unreadable/changing files and duplicate JSON keys are refused. This is a bounded
snapshot check, not filesystem confinement or a whole-host inventory. Supported
containers are the legacy bare array and `{mcpmSchemaVersion: 2, servers: [...]}`;
unknown schema versions are incomplete. Rows require a bounded coordinate name,
nonempty control-free version, known client IDs and an ISO timestamp. Invalid
rows become indexed gaps without echoing their values; the first valid row for
a name is retained and later duplicates are gaps. Valid siblings are assessed.

## Consume coverage and findings together

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `1`; accept additive fields/reason codes, stop on unknown versions |
| `source` / `metadataSelector` | `mcpm-store` / `latest`; no installed-version or native-loading claim |
| `scope` | `selectedChecks` names registry/static and configured external assessment; `excludes` names unassessed health, installed bytes, client configuration and native activation |
| `inventory` | `state`: `complete`, `empty` or `incomplete`; `presence`: `missing`, `present` or `unknown`; `total`: source row count or `null` if unavailable; `accepted`: valid unique rows; `issues`: fixed `code` and optional zero-based row `index` |
| `assessmentComplete` | Inventory is complete and every accepted row completed registry/static and, when configured, external assessment. Explicitly unselected checks do not make this false; it never means all safety checks passed |
| `outcome` | `empty_inventory`, `no_findings`, `findings` or `incomplete_assessment`. Incompleteness takes precedence and retains any findings from assessed siblings |
| `summary` | `assessed`: rows completing selected checks; `unassessed`: total minus assessed, or `null` if inventory total is unknown; `findingCount`: retained findings, excluding scanner failure diagnostics |
| `servers[]` | Valid unique name, nullable existing `score` object, reduced `findings` and per-item `checks` |
| `checks` | `registry`, `static`, `external`, `health`, each with `state`: `performed`, `not_run`, `unavailable` or `failed`, plus an optional fixed `reason` |

`no_findings` means no findings from the selected bounded checks, never safety or
complete host coverage. Empty inventory is a separate result, including a missing
store. `not_run`, `unavailable` and `failed` do not grant passed-check credit.
Health is always `not_run`. An unconfigured external scanner is `not_run`; a
configured but unrunnable/refused scanner is `unavailable`; unreadable/malformed
scanner output is `failed`. `performed` for external scanning means the existing
adapter obtained parseable findings, including valid output on a nonzero process
exit. It is not an attestation that the scanner succeeded or behaved safely.

A failed registry/static row has `score: null`, rather than a fabricated risky
score. Registry failure reasons distinguish `not-found`, `unrecognised-response`,
`unavailable` and `unknown`; mismatched response names fail with
`identity-mismatch`. Raw exception text is omitted. Scanner failures remain
coverage diagnostics rather than evidence about the server. Existing score
calculation still receives the same static/external evidence and unrun health
input; failed/unavailable external checks receive no external credit.

Findings retain only severity, type and source. Raw messages, locations, parser
errors, OS paths, configured scanner commands and registry error text are omitted.
Names are retained identifiers and untrusted data, not instructions. This is not
an anonymous or universally redacted public bug report; review identifiers before
sharing it. The separate `doctor --report` remains redacted human-readable text.

Exit `1` means incomplete assessment or an existing risky score. Exit `0` can
mean an empty inventory, advisory findings or bounded no-findings, with unrun
health/external checks still visible. Do not use exit status alone as a safety
gate. `--report-json` rejects `--json`, `--sarif`, `--fix`, `--min-trust` and
`--yes` combinations with exit `2`, before inventory reads. Existing text,
`--json` bare-array/fix-wrapper behavior, SARIF and `mcpm_audit` are unchanged;
their older coverage limitations remain. No new MCP input or served tool is added.
