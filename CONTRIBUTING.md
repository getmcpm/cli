# Contributing to mcpm

Thanks for your interest. mcpm is a security tool, so the bar is correctness and
determinism over feature breadth.

## Development setup

Requires **Node.js `^22.22.2 || ^24.15.0 || >=26.0.0`** and **pnpm 10**. That range is
the intersection of every runtime dependency's own `engines`, not a preference —
`src/__tests__/engines-invariant.test.ts` fails the build if `package.json` promises
a Node a dependency does not support.

```
pnpm install            # frozen lockfile
pnpm run typecheck      # tsc --noEmit (this is also `lint`)
pnpm run build          # tsup -> dist/
pnpm test               # vitest
pnpm run test:coverage  # with coverage
```

`@types/node` is pinned to the engines floor (22), so a local `typecheck` only proves
the code compiles against Node 22's API. CI re-runs it per matrix leg against that
leg's own typings. To reproduce a `Typecheck against @types/node <major>` failure:

```
pnpm add -D @types/node@26   # or 24 — the major CI failed on
pnpm run typecheck
git checkout -- package.json pnpm-lock.yaml
```

### Dogfooding a release

`pnpm dogfood:release` packs the tarball, clean-installs it, and smoke-runs the real
binary. It gates `pnpm publish`, so it runs against your *local* build and needs a Node
inside `engines.node`.

To smoke an **already-published** version instead, set `MCPM_DOGFOOD_SPEC` — the same
script, same assertions, no build and no pnpm:

```
MCPM_DOGFOOD_SPEC=@getmcpm/cli@latest ./scripts/dogfood-release.sh
```

Three places to run that, in increasing order of "not your machine":

| where | how | good for |
|---|---|---|
| your machine | the command above | fastest, but needs a conforming Node, and it is your machine |
| a container | `docker run --rm -v "$PWD/scripts:/w/scripts:ro" -w /w -e MCPM_DOGFOOD_SPEC=@getmcpm/cli@latest node:26 ./scripts/dogfood-release.sh` | any Node major, disposable, no local Node needed |
| GitHub | Actions → **Dogfood** → *Run workflow* | Node 22/24/26 + macOS, zero local setup |

The smoke run uses a throwaway `$HOME`, so `doctor` sees a clean machine and nothing
touches your real `~/.mcpm` or MCP client configs. `dogfood-confine.sh` does the same.
Verified: after a full run in a container, `$HOME/.mcpm` does not exist.

macOS-only end-to-end check for the `--confine` sandbox:

```
pnpm dogfood:confine    # hermetic; must print "✓ confine dogfood PASSED"
```

## Ground rules

- **Tests first, and they must pass.** New behaviour needs a test; bug fixes need a
  failing repro test that your change turns green. Keep the suite and `typecheck`
  green — CI runs them on Node 22/24/26.
- **Local-first, deterministic, no telemetry.** The default path makes no model-API
  calls and sends no usage data. Don't add a hosted backend or a network call on a
  path the user didn't ask for. New runtime dependencies are avoided; if one is
  genuinely needed, call it out explicitly in the PR.
- **Validate at the boundary.** External data (registry responses, config files, tool
  traffic) is parsed through Zod before use. Fail closed on integrity/security
  boundaries; state boundaries honestly in user-facing copy.
- **Conventional commits.** `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`,
  `perf:`, `ci:`. Update `CHANGELOG.md` under `## [Unreleased]` for user-visible
  changes.

## Pull requests

Keep PRs single-purpose and small enough to review. Describe the problem, the change,
and how you verified it. Changes under `.github/workflows/` require `CODEOWNERS`
review.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — please do **not** open a public issue for a
vulnerability.
