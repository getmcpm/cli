# `mcpm verify` GitHub Action

A fail-closed CI gate that verifies your committed `mcpm-lock.yaml` against npm's
**published** `dist.integrity` record. It runs `mcpm verify` — repo-only, no AI
clients required — so it works on a hosted runner where `mcpm up` cannot.

The step fails (non-zero) on integrity **drift**, an **unverifiable** record, an
integrity **format mismatch**, or a **suspicious missing baseline**, and writes a
job **step summary** from the `--json` model.

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
      - uses: getmcpm/cli/.github/actions/mcpm-verify@v0.19.0
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

`0` verified · `1` block (integrity drift / unverifiable / format mismatch /
missing baseline) or no lock file found. See `docs/CONTRACTS.md`.
