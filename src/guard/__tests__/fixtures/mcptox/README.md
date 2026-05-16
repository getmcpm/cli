# mcpm-guard fixture corpus

> ⚠ **Caution — fixture content (security review Step 8 F3).** The `attacks/`
> fixtures contain real prompt-injection payloads used to exercise the
> detection engine. Do NOT copy fixture strings verbatim into prompts, AI
> assistant contexts, or issue trackers. If your IDE's AI assistant has
> passive file-context ingestion (e.g. workspace-wide file scanning), keep
> `fixtures/mcptox/attacks/` out of its workspace scope.

Deterministic attack + benign fixtures used by `mcptox.test.ts` to gate CI.

**Why hand-authored vs vendored MCPTox?** OQ3 of the v0.5.0 design doc flagged
MCPTox redistribution licensing as unresolved. These fixtures are derived
from public attack methodology (Invariant Labs disclosure 2025, MCPoison
CVE-2025-54136, Equixly / Pillar Security audit findings) — no MCPTox
artifacts are copied. License-clean.

## Layout

- `attacks/` — JSON fixtures that MUST trigger a `block` or `warn` action.
- `benign/`  — JSON fixtures that MUST trigger a `pass` (no findings).
- `drift/`   — Schema-drift fixtures; require pre-pinning, run via a
  separate test that captures a pin then replays a mutated tools/list.

## Fixture schema

```json
{
  "name": "human-readable name",
  "category": "OWASP-MCP-N",
  "expected_action": "block" | "warn" | "pass",
  "expected_signature_id": "...",   // omit for benign/pass
  "notes": "where the attack methodology came from",
  "message": { /* JSONRPCMessage to feed inspectMessage() */ }
}
```

## Coverage matrix (v0.5.0)

| OWASP-MCP-N | Attack class                 | Fixtures |
|-------------|------------------------------|----------|
| 1           | Tool-description injection   | 4 (incl. rug-pull + system-tag) |
| 2           | Response instruction injection | 7 (incl. NFKC + ZWSP + newline + soft-hyphen + bidi + disregard/forget) |
| 7           | Path exfil in args           | 3 (.ssh / .aws / .env) |
| —           | Benign corpus                | 8 |
| —           | Schema drift                 | 3 (incl. MCPoison-equivalent) |

Refresh policy: when a new OWASP MCP Top 10 category is added or a public
CVE discloses a new attack class, add a fixture here in the same PR that
adds the signature.
