# Launch Checklist

## Pre-launch (day before)

- [ ] All tests pass: `pnpm test`
- [ ] Build succeeds: `pnpm build`
- [ ] Local install works: `npm install -g .` then `mcpm --help`
- [ ] `mcpm search filesystem` returns real results from the registry
- [ ] `mcpm install <server-name>` completes with trust score (e.g. `io.github.domdomegg/filesystem-mcp`)
- [ ] `mcpm doctor` runs without errors
- [ ] `mcpm audit` produces a trust report (install a server first)
- [ ] `mcpm init developer` installs all three servers
- [ ] README has demo GIF (or placeholder comment)
- [ ] GitHub repo description set: "MCP package manager with built-in trust scoring"
- [ ] GitHub topics set: mcp, model-context-protocol, package-manager, cli, ai, security
- [ ] npm org (@getmcpm) is ready and has publish access configured

## Launch day

- [ ] Tag v0.1.0: `git tag v0.1.0 && git push --tags`
- [ ] CI publishes to npm (verify: `npm view @getmcpm/cli`)
- [ ] Verify global install: `npm install -g @getmcpm/cli && mcpm --version`
- [ ] Record demo GIF: `asciinema rec --command="./scripts/demo.sh" demo.cast`
- [ ] Convert to GIF: `agg demo.cast demo.gif` or use VHS
- [ ] Add GIF to README, push final version to GitHub

## Post on HN

- [ ] Title: "Show HN: mcpm -- MCP package manager with built-in trust scoring"
- [ ] Body includes: the 66% stat, link to repo, `npm install -g @getmcpm/cli`
- [ ] Post timing: weekday, 9-10am ET
- [ ] Monitor: GitHub issues for first-hour bugs
- [ ] Respond to HN comments within first 2 hours

## Cross-post

- [ ] r/ClaudeAI
- [ ] r/cursor
- [ ] AI Discord servers (Claude, Cursor, general AI dev)
- [ ] DEV.to article (longer form, explain the security angle)

## Post-launch (first week)

- [ ] Respond to all GitHub issues within 24 hours
- [ ] Track npm download count daily
- [ ] Note feature requests for V1.1 in GitHub issues
- [ ] If major bugs: patch release v0.1.1 within 24 hours
- [ ] Write a short retrospective: what worked, what didn't
