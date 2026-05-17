# Legitimate session corpus (FP-rate measurement)

Per-session JSONL captures from real-world MCP servers. The fp-rate test
runner inspects every JSON-RPC message through the production engine and
asserts the **false-positive rate stays below 2%** (design doc Success Criterion).

## Format

One JSON-RPC message per line. Empty lines + lines starting with `#` are skipped.

```
# Comment line — describes a phase
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05",...}}
{"jsonrpc":"2.0","id":2,"result":{"tools":[...]}}
# Each session should include initialize + tools/list + several tools/call round-trips
```

## v0.5.0 seed (5 sessions)

| Server                  | File                              | Messages | Notes |
|-------------------------|-----------------------------------|----------|-------|
| filesystem-mcp          | `filesystem-mcp.jsonl`            | 6        | read_file / write_file / list_directory |
| github-mcp              | `github-mcp.jsonl`                | 5        | search_issues / get_repo — issue title contains "ignore" (FP trap) |
| slack-mcp               | `slack-mcp.jsonl`                 | 5        | read_channel returns thread with the word "ignore" in non-imperative context |
| postgres-mcp            | `postgres-mcp.jsonl`              | 5        | query / list_tables — schema includes a column literally named `description` |
| fetch-mcp               | `fetch-mcp.jsonl`                 | 4        | fetches a documentation page ABOUT prompt injection (most adversarial benign case) |

These are synthetic-but-realistic — modeled on actual `@modelcontextprotocol/servers-*`
response shapes. The hard FP cases (documentation about prompt injection, an
issue whose title contains "ignore", etc.) are intentional adversarial benign
cases: if these false-positive, the engine is too sensitive to ship.

## Known engine limitation surfaced by the seed corpus

A documentation page that contains the **verbatim** trigger phrase ("disregard
prior instructions", "ignore previous instructions" written out exactly) WILL
false-positive — the regex engine cannot distinguish meta-discussion from
instruction. The fetch-mcp.jsonl fixture intentionally writes documentation
content that **describes** attack patterns rather than quoting them verbatim,
which mirrors how real security docs are usually written. If you add a fixture
that includes a verbatim attack phrase as benign content, the test will fail
and that's the engine being honest about its limit, not a fixture bug.

Future engines could use context-aware detection (LLM-as-judge over a
documentation/instruction window — see v0.5.1+ roadmap), but v0.5.0 ships
without it.

## Refresh policy (post-v0.5.0)

Per design doc Reviewer Concern #11 + TODOS entry #29:
- Maintainer captures fresh 5-minute sessions against each top-20 server every quarter
- Capture script (`scripts/capture-fp-session.ts`, not yet written) tees stdio
  through `mcpm guard run --inner` + writes to a JSONL
- CI publishes the FP rate per release in the release notes

The 20-server full corpus is logged as TODOS entry #29; v0.5.0 ships with
this 5-session seed (25 messages total).
