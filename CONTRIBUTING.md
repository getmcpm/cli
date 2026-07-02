# Contributing to mcpm

Thanks for your interest. mcpm is a security tool, so the bar is correctness and
determinism over feature breadth.

## Development setup

Requires **Node.js >= 22** and **pnpm 10**.

```
pnpm install            # frozen lockfile
pnpm run typecheck      # tsc --noEmit (this is also `lint`)
pnpm run build          # tsup -> dist/
pnpm test               # vitest
pnpm run test:coverage  # with coverage
```

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
