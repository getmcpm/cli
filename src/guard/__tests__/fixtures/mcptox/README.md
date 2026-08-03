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
- `warn/`    — retrieved-data carriers that MUST `warn` and be forwarded, never
  dropped (see the note below).
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

## Layout note — `warn/`

`warn/` holds retrieved-data carriers (resource / prompt content) where a
signature match is annotated and **forwarded**, never dropped. They are neither
clean attacks nor clean benigns, so they assert the warn-only carrier clamp (H1)
in their own block.

## Coverage matrix (v0.28.x)

| Category | Attack class | Fixtures |
|---|---|---|
| OWASP-MCP-1 | Tool-description / metadata injection | 11 (incl. system-tag, ANSI, bidi, ZWSP, Unicode TAG block ×2, multi-tool poisoning, `initialize.instructions`, plus the structural `exfil-param-in-schema` key detector) |
| OWASP-MCP-2 | Response instruction injection | 8 attacks (incl. NFKC, ZWSP, newline, homoglyph, disregard/forget, developer-mode) + 3 warn-tier (resource / prompt content) |
| OWASP-MCP-7 | Path exfil in args | 3 (.ssh / .aws / .env) |
| MCP-CREDENTIAL-EXFIL | Credential egress in responses (F10) | 2 (GitHub PAT, PEM private key) |
| MCP-CREDENTIAL-PHISHING | Server-initiated credential solicitation (F6) | 2 (wallet seed phrase, card CVV) |
| — | Benign corpus (FP-rate seed) | 14 |
| — | Schema drift | 3 (incl. the MCPoison-equivalent rug-pull) |

Every signature in the shipped catalog must have at least one fixture here, and
every attack/warn fixture must be caught through the public `mcpm guard inspect`
seam — `inspect-relay-parity.test.ts` fails the build otherwise, with a justified
allowlist for signatures that need a frame no fixture can reasonably carry.

Refresh policy: when a new OWASP MCP Top 10 category is added or a public
CVE discloses a new attack class, add a fixture here in the same PR that
adds the signature.
