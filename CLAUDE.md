# Claude Code entry point

@AGENTS.md

Shared contributor instructions live in AGENTS.md; keep this file a thin import.
Claude project skills under `.claude/skills/` refer to the canonical repo-owned
`.agents/skills/` workflows. Read their linked SKILL.md when selected; do not
import the historical archive into session context. See
[loading and current context](docs/MAINTAINER-WORKFLOW.md).

Claude terminal tools need Node.js `^22.22.2 || ^24.15.0 || >=26.0.0` and pnpm 10.
This range remains explicit here for the existing engines documentation check.

If gstack is installed, prefer its `/browse` workflow for browsing; do not use
`mcp__claude-in-chrome__*`. gstack is optional, not a contributor dependency.
For an existing local gstack installation, follow its own setup/help if needed;
do not install plugins or change global permissions as part of an unrelated task.
