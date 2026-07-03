# Distribution

mcpm ships as the scoped npm package **`@getmcpm/cli`** (bin: `mcpm`). Every install
channel below resolves that one package, so there is no ambiguity about what you get.

## Install matrix

| Method | Command | Notes |
|---|---|---|
| **npm** | `npm install -g @getmcpm/cli` | global bin `mcpm` |
| **npx** | `npx @getmcpm/cli <command>` | no install; always latest |
| **pnpm** | `pnpm add -g @getmcpm/cli` | |
| **mise** | `mise use -g npm:@getmcpm/cli` | via mise's built-in `npm:` backend — no registry entry needed |

`npx @getmcpm/cli` is what the CI surfaces (`mcpm verify`, `mcpm audit --sarif`) and
the GitHub Action use, so it is the most-exercised path.

## The `mcpm` name collision (why no `brew install mcpm`)

An **unrelated** project — Path Integral's [mcpm.sh](https://mcpm.sh) — already owns
the short name `mcpm`:

- it is the **`mcpm` formula in Homebrew core** ("Open source, community-driven MCP
  server and client manager", homepage `mcpm.sh`), and
- it squats the `mcpm` name on PyPI.

Its bin is also called `mcpm`. So we deliberately **do not** publish a colliding
`brew install mcpm` or claim the `mcpm` short-name on registries that already point at
mcpm.sh — that would fight over a name we don't own and would conflict on the `mcpm`
binary if a user had both installed.

**Resolution:** distribute through the scoped, collision-free channels above
(`@getmcpm/cli` on npm; `npm:@getmcpm/cli` on mise). The `getmcpm` scope and the
`getmcpm/cli` repo are the canonical identity.

## Deferred

- **Homebrew tap** (`getmcpm/homebrew-mcpm`) — a tap could ship a non-colliding
  formula (e.g. `getmcpm`), but it needs a separate repo under the org and a decision
  on the installed bin name (it can't shadow core `mcpm`). Deferred until there's
  demand the npm/npx/mise channels don't already cover.
- **mise registry short-name** (`mise use mcpm`) — would require a PR to the mise
  registry for a name that resolves to mcpm.sh's world; the `npm:@getmcpm/cli` backend
  form works today without it.
- **devcontainer feature** — deferred until a project-scope adapter exists (inside a
  container there are no host GUI client configs to manage).
