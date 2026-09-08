/**
 * OWASP MCP Top 10 (beta) pin — carried on every finding a guard tool emits.
 *
 * backlog #71: "the pin travels in the record." Every finding is classified
 * against ONE spec commit, in one of three states:
 *   - `pinned`    — maps to a category as of OWASP_MCP_TOP_10_REF
 *   - `unknown`   — not yet classified against this commit (never fabricated)
 *   - `unpinnable`— evaluated and does NOT correspond to any category (a
 *                   guard/relay health signal, not an attack class)
 *
 * The mapping is a side TABLE, not a field on `Signature`, because it must
 * also cover signature_ids that are emitted directly (drift.ts, patterns.ts,
 * relay.ts, run-inner.ts) and never appear as a catalog entry in signatures.ts.
 *
 * Values come from docs/owasp-mcp-mapping.md — do not add or change a mapping
 * here without a corresponding row/mention in that doc. See its "The pin
 * travels in the record" section and "Not yet classified" subsection.
 */

import type { Finding } from "../scanner/tier1.js";

/** Must equal the sha pinned in docs/owasp-mcp-mapping.md — owasp.test.ts checks this. */
export const OWASP_MCP_TOP_10_REF = "165fe0f78ef104459237b4a8e0f6e78db9b02391";
export const OWASP_MCP_TOP_10_URL = `https://github.com/OWASP/www-project-mcp-top-10/tree/${OWASP_MCP_TOP_10_REF}`;

export type OwaspMcpId =
  | "MCP01"
  | "MCP02"
  | "MCP03"
  | "MCP04"
  | "MCP05"
  | "MCP06"
  | "MCP07"
  | "MCP08"
  | "MCP09"
  | "MCP10";

export type OwaspPin =
  | { readonly status: "pinned"; readonly id: OwaspMcpId; readonly ref: string }
  | { readonly status: "unknown"; readonly ref: string }
  | { readonly status: "unpinnable"; readonly ref: string };

/** The ten official OWASP MCP Top 10 (beta) category short names, at OWASP_MCP_TOP_10_REF. */
export const OWASP_MCP_TOP_10_TAXA: ReadonlyArray<{ readonly id: OwaspMcpId; readonly name: string }> = [
  { id: "MCP01", name: "Token Mismanagement & Secret Exposure" },
  { id: "MCP02", name: "Privilege Escalation via Scope Creep" },
  { id: "MCP03", name: "Tool Poisoning" },
  { id: "MCP04", name: "Software Supply Chain Attacks & Dependency Tampering" },
  { id: "MCP05", name: "Command Injection & Execution" },
  { id: "MCP06", name: "Intent Flow Subversion" },
  { id: "MCP07", name: "Insufficient Authentication & Authorization" },
  { id: "MCP08", name: "Lack of Audit and Telemetry" },
  { id: "MCP09", name: "Shadow MCP Servers" },
  { id: "MCP10", name: "Context Injection & Over-Sharing" },
];

type PinState = OwaspMcpId | "unknown" | "unpinnable";

/**
 * Explicit per-signature_id classification. `_TEST_ONLY` prefix marks the
 * export as test-consumption only (exhaustiveness check in owasp.test.ts) —
 * not part of the module's real API.
 */
export const _SIGNATURE_OWASP_TABLE: Readonly<Record<string, PinState>> = {
  // ── MCP01 — Token Mismanagement & Secret Exposure ─────────────────────────
  "credential-egress-in-response": "MCP01",
  "generic-bearer-token-disclosure": "MCP01",

  // ── MCP02 — Privilege Escalation via Scope Creep ──────────────────────────
  "handshake-drift-capability": "MCP02",

  // ── MCP03 — Tool Poisoning ─────────────────────────────────────────────────
  "owasp-mcp-1-tool-description-injection": "MCP03",
  "owasp-mcp-2-instruction-injection-in-response": "MCP03",
  "hidden-chars-in-metadata": "MCP03",
  "unicode-tag-concealment": "MCP03",
  "exfil-param-in-schema": "MCP03",
  "schema-drift": "MCP03",
  "schema-drift-cosmetic": "MCP03",
  "schema-drift-in-session": "MCP03",
  "owasp-mcp-1-tool-annotation-injection": "MCP03",
  "tool-name-confusable-duplicate": "MCP03",
  "tool-name-deceptive-characters": "MCP03",

  // ── MCP05 — Command Injection & Execution ─────────────────────────────────
  "shell-metachar-in-identifier-arg": "MCP05",
  "query-control-syntax-in-identifier-arg": "MCP05",
  "cli-flag-injection-in-identifier-arg": "MCP05",

  // ── MCP06 — Intent Flow Subversion ─────────────────────────────────────────
  "owasp-mcp-2-instruction-injection-in-resource": "MCP06",
  "owasp-mcp-2-instruction-injection-in-prompt": "MCP06",
  "owasp-mcp-1-initialize-instruction-injection": "MCP06",
  "credential-phishing-wallet-solicitation": "MCP06",
  "credential-phishing-financial-solicitation": "MCP06",

  // ── unknown — not yet classified against OWASP_MCP_TOP_10_REF ─────────────
  // (docs/owasp-mcp-mapping.md "Not yet classified" subsection)
  "owasp-mcp-7-path-exfil-in-args": "unknown",
  "renderer-code-execution-in-response": "unknown",
  // The doc explicitly refuses to count identity drift under MCP07 (anti-
  // impersonation, not authentication/authorization) and does not count it
  // anywhere else.
  "handshake-drift-identity": "unknown",
  // Compares the WHOLE handshake hash (hashHandshake() of BOTH capabilities
  // AND serverName field hashes together — see HandshakeFieldHashes,
  // src/guard/pins.ts) against the same-session baseline, so it fires on
  // EITHER dimension changing, not exclusively capability. Not the clean
  // in-session variant of MCP02 the spec asked to confirm.
  "handshake-drift-in-session": "unknown",

  // ── unpinnable — guard/relay health signals, not an attack class ──────────
  "guard-inspection-truncated": "unpinnable",
  "pins-integrity-failure": "unpinnable",
  "orig-hash-mismatch": "unpinnable",
  "spawn-failure": "unpinnable",
  "inspect-rejected": "unpinnable",
  "malformed-frame": "unpinnable",
};

/** Ids absent from the table classify as `unknown` — never fabricate a category. */
export function owaspPinFor(signatureId: string): OwaspPin {
  const state = _SIGNATURE_OWASP_TABLE[signatureId];
  if (state === undefined || state === "unknown") {
    return { status: "unknown", ref: OWASP_MCP_TOP_10_REF };
  }
  if (state === "unpinnable") return { status: "unpinnable", ref: OWASP_MCP_TOP_10_REF };
  return { status: "pinned", id: state, ref: OWASP_MCP_TOP_10_REF };
}

/**
 * Scanner (tier-1) `Finding.type` → OWASP pin, for SARIF taxonomy
 * relationships (`mcpm audit --sarif`). A separate, TS-exhaustive table from
 * the signature-id one above — same doc, different emitter surface. Values
 * from docs/owasp-mcp-mapping.md's MCP01/MCP03/MCP04/MCP05 rows.
 */
const SCANNER_TYPE_OWASP: Readonly<Record<Finding["type"], OwaspMcpId | "unpinnable">> = {
  secrets: "MCP01",
  "prompt-injection": "MCP03",
  "exfil-args": "MCP03",
  typosquatting: "MCP04",
  "release-cooldown": "MCP04",
  "registry-status": "MCP04",
  "install-script": "MCP05",
  "scanner-error": "unpinnable",
};

export function owaspPinForScannerType(type: Finding["type"]): OwaspPin {
  const state = SCANNER_TYPE_OWASP[type];
  if (state === "unpinnable") return { status: "unpinnable", ref: OWASP_MCP_TOP_10_REF };
  return { status: "pinned", id: state, ref: OWASP_MCP_TOP_10_REF };
}
