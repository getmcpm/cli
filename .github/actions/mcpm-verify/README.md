# `mcpm verify` GitHub Action

A fail-closed CI gate over your committed `mcpm-lock.yaml`. It runs `mcpm verify` —
repo-only, no AI clients required — so it works on a hosted runner where `mcpm up`
cannot, and it checks three independent dimensions:

1. **Integrity** — each locked npm server against npm's **published** `dist.integrity`.
2. **Provenance (Sigstore)** — for every server the lock recorded as cryptographically
   `verified`, the npm SLSA attestation is **re-verified offline** and the signer
   identity compared against the locked baseline. Evidence-gated: a lock with no
   verified baseline is unaffected.
3. **Coverage** — every server `mcpm.yaml` declares must appear in the lock, so a
   truncated lock cannot pass vacuously.

The step fails (non-zero) on integrity **drift**, an **unverifiable** record, an
integrity **format mismatch**, a **suspicious missing baseline**, a provenance
**signer-changed** / **regression** / **unverifiable** verdict, **uncovered** declared
servers, or a **vacuous** run (an empty lock with no `mcpm.yaml` to confirm that is
intentional). It writes a job **step summary** from the `--json` model naming every
blocking server and its reason, grouped by dimension.

> Honesty boundary: a failure means npm's *published record* diverged from (or
> can't be matched against) your lock — **not** that mcpm caught malicious bytes.
> npx/uvx fetch the artifact independently at server launch.

## Usage

Pin the action to a release SHA (or tag):

```yaml
name: mcpm
on: [push, pull_request]
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: getmcpm/cli/.github/actions/mcpm-verify@v0.39.0
        # with:
        #   version: latest          # @getmcpm/cli version/dist-tag to run
        #   working-directory: .     # dir containing mcpm.yaml / mcpm-lock.yaml
```

Equivalent one-liner (no action):

```yaml
      - run: npx --yes @getmcpm/cli verify
```

Pre-commit hook (same verb):

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: mcpm-verify
      name: mcpm verify
      entry: npx --yes @getmcpm/cli verify
      language: system
      pass_filenames: false
```

## Badge

Once the gate is in your CI, advertise it with a static badge:

```markdown
![mcpm verified](https://img.shields.io/badge/mcpm-verified-brightgreen)
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `version` | `latest` | Version or dist-tag of `@getmcpm/cli` to run. |
| `working-directory` | `.` | Directory containing `mcpm.yaml` / `mcpm-lock.yaml`. |

## Exit codes

`0` verified · `1` block or no lock file found. A block is any of: integrity drift /
unverifiable / format mismatch / missing baseline; a provenance signer-changed /
regression / unverifiable verdict; declared servers the lock does not cover; or a
vacuous run over an empty lock. See `docs/CONTRACTS.md`.
