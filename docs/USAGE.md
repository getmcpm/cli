# CLI workflows and command index

Use `mcpm <command> --help` for the current options and flags. Search results show
registry lifecycle status; use `info` or `why` for computed trust evidence. Installation
changes client configuration; runtime inspection requires explicit `guard enable` and a
server restart. See [trust](TRUST.md) and [guard](GUARD.md).

## Stacks and CI

Declare your project's MCP servers in `mcpm.yaml`, lock versions with trust snapshots,
and let every team member replicate the setup with one command.

```bash
mcpm export > mcpm.yaml          # dump current setup
mcpm lock                        # resolve versions + trust snapshot
mcpm up                          # install everything from mcpm.yaml
mcpm diff                        # compare installed vs declared state
```

Stack files include a trust policy. If a server's trust score drops below the threshold,
`mcpm up` blocks it.

Locks record the MCP publication version separately from the actual package version.
`up` verifies the locked package tuple before writing any client config, then launches
that npm/PyPI version or explicit OCI tag/digest. Old locks without package-version
evidence need `mcpm lock` again. OCI tags remain mutable, and integrity checks compare
registry records; mcpm does not intercept the bytes that package managers download at
launch.

The identifiers/versions below are illustrative; replace them with candidates and
versions you have assessed with `search`/`info`/`why`.

```yaml
version: "1"
policy:
  minTrustScore: 60
  blockOnScoreDrop: true
servers:
  io.github.acme/filesystem-mcp:
    version: "^1.0.0"
  io.github.acme/github-mcp:
    version: "1.2.3"
    env:
      GITHUB_TOKEN: { required: true, secret: true }
```

### Scaffold a stack file

Start a new project's MCP setup in one command. `mcpm init` writes a starter `mcpm.yaml`
you fill in with servers from `mcpm search`.

```
$ mcpm init

Created mcpm.yaml.

  Next steps:
    mcpm search <query>   find MCP servers in the registry
    edit mcpm.yaml        add them under `servers:`
    mcpm lock             resolve and lock versions
    mcpm up               install from the stack file
```

It refuses to clobber an existing `mcpm.yaml` (pass `--force` to overwrite). mcpm
deliberately doesn't ship curated packs — blessing specific community servers is a trust
decision a security tool shouldn't bake in.

Commit `mcpm.yaml` and `mcpm-lock.yaml`; run `mcpm verify` in CI without installed AI
clients. `up --frozen` applies the integrity/provenance freeze before installation.
Review drift instead of automatically re-locking it. See the [verification
Action](../.github/actions/mcpm-verify/README.md) and [versioned
contracts](CONTRACTS.md) for failure and coverage semantics.

`mcpm audit --sarif > mcpm.sarif` produces GitHub code-scanning input. Audit exits 1 for
risky servers and 2 for an unsatisfied invocation. SARIF is report-only and cannot be
combined with `--fix`; upload the report even when findings make audit nonzero. See [the
audit contract](CONTRACTS.md).

## Commands

| Command | Description | |---|---| | `mcpm search <query>` | Search the MCP registry
for servers | | `mcpm install <name>` | Install an MCP server from the registry | |
`mcpm info <name>` | Show full details for an MCP server | | `mcpm list` | List all
installed MCP servers across detected AI clients | | `mcpm remove <name>` | Remove an
MCP server from client config(s) | | `mcpm audit` | Scan all installed servers and
produce a trust report (`--json`, `--sarif` for GitHub code-scanning) | | `mcpm update`
| Check for newer versions and update installed servers | | `mcpm outdated` | Show
version drift for installed servers (use `mcpm audit` for current security findings) | |
`mcpm secrets` | Manage MCP server credentials (AES-GCM encrypted at rest; key held in
the OS keychain — macOS Keychain / libsecret / Windows DPAPI — so a copied store can't
be decrypted off-machine, with a machine-derived-key fallback where no keychain is
available). `mcpm secrets migrate` upgrades older entries | | `mcpm publish scaffold` |
Create a .mcpm-publish.yaml manifest interactively | | `mcpm publish check` | Dry-run:
show trust score and what would be submitted (`--json` emits the exact request body) | |
`mcpm publish` | Submit to the official MCP registry (requires
`GITHUB_TOKEN`/`MCPM_TOKEN`, or `--github-oidc` in GitHub Actions with `id-token:
write`) | | `mcpm scope <project-root>` | Read-only source/instruction metadata
inventory (`--json`); Claude Code by default, explicit `--client vscode` for distinct VS
Code/Copilot candidates; [coverage and unknown states](PROJECT-SCOPE.md) | | `mcpm
review-artifacts <before.tar> <after.tar> --profile <profile>` | Compare explicit local
USTAR Agent Skills or Claude plugin snapshots, with byte/mode changes, declarations,
literal references and coverage gaps (`--json`); [format and limits](ARTIFACT-REVIEW.md)
| | `mcpm doctor` | Check MCP setup health and report issues (`--json` structured model,
`--report` redacted paste-for-bug-reports snapshot) | | `mcpm init` | Scaffold a starter
`mcpm.yaml` stack file in the current directory | | `mcpm disable <name>` | Disable an
MCP server without removing it from config | | `mcpm enable <name>` | Re-enable a
previously disabled MCP server | | `mcpm import` | Import existing MCP servers from
client config files | | `mcpm alias` | Create short aliases for long MCP server names |
| `mcpm export` | Export installed servers as an mcpm.yaml stack file | | `mcpm lock` |
Resolve versions and create mcpm-lock.yaml with trust snapshots (+ npm provenance
identity, WARNs on drift) | | `mcpm up` | Install all servers from mcpm.yaml with trust
verification | | `mcpm verify` | Repo-only CI gate: verify lockfile integrity +
re-verify Sigstore provenance vs npm's published record (`--json`) | | `mcpm diff` |
Compare installed servers against mcpm.yaml and lock file | | `mcpm sync` | Show
cross-client config drift across all detected clients (`--check` gates CI with exit 2,
`--json`) | | `mcpm completions <shell>` | Generate shell completion scripts (bash, zsh,
fish) | | `mcpm why <name>` | Explain a server's trust score (breakdown of all
components) | | `mcpm serve` | Start mcpm as an MCP server (stdio transport) | | `mcpm
guard enable` | Wrap detected client configs with the inspection relay; Claude Code
stdio gets a [file-policy preflight](MANAGED-POLICY-VALIDATION.md), with host coverage
unknown | | `mcpm guard disable` | Restore original client configs | | `mcpm guard
status` | Show what's wrapped and the per-server pin state | | `mcpm guard demo` | Run
the synthetic prompt-injection scenario (visible block) | | `mcpm guard accept-drift
<server>` | Re-pin a tool's schema after a legitimate upgrade | | `mcpm guard mute
<signature-id>` | Disable a signature with optional `--for <duration>` | | `mcpm guard
unmute <signature-id>` | Re-enable a muted signature | | `mcpm guard pause` | Pause all
guard inspection (debugging escape hatch) | | `mcpm guard cleanup` | Prune pin entries
for uninstalled servers | | `mcpm guard inspect [file]` | Run the signature catalog over
MCP JSON-RPC frame(s), offline — no relay, no server | | `mcpm guard list-signatures` |
Show the shipped OWASP MCP Top 10 signature catalog | | `mcpm guard doctor-confine` |
Report sandbox-backend availability and which servers are enrolled in confinement
(`--json`) | | `mcpm guard reset-integrity` | Regenerate the pins.json or
guard-policy.yaml integrity sidecar |

Run `mcpm <command> --help` for options and flags.
