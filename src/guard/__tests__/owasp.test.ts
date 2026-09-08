/**
 * The OWASP MCP Top 10 pin (backlog #71) — src/guard/owasp.ts.
 *
 * The load-bearing property is EXHAUSTIVENESS: every signature_id the guard
 * can actually emit (the catalog in signatures.ts, plus every literal
 * `signature_id: "..."` written directly in a non-test src/guard/*.ts file)
 * must have an EXPLICIT entry in the table — so a new signature can't ship
 * unclassified and silently default to "unknown".
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { OWASP_MCP_TOP_10 } from "../signatures.js";
import {
  owaspPinFor,
  owaspPinForScannerType,
  OWASP_MCP_TOP_10_REF,
  _SIGNATURE_OWASP_TABLE,
} from "../owasp.js";
import type { Finding } from "../../scanner/tier1.js";

const GUARD_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."); // src/guard/__tests__/.. -> src/guard

/** Every literal `signature_id: "<id>"` written directly in a non-test src/guard/*.ts file. */
function emittedSignatureIds(): string[] {
  const ids = new Set<string>();
  for (const name of readdirSync(GUARD_DIR)) {
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    const text = readFileSync(path.join(GUARD_DIR, name), "utf-8");
    for (const m of text.matchAll(/signature_id:\s*"([^"]+)"/g)) {
      const id = m[1];
      if (id !== undefined) ids.add(id);
    }
  }
  return [...ids];
}

describe("owaspPinFor — exhaustiveness", () => {
  it("every OWASP_MCP_TOP_10 catalog id has an explicit table entry", () => {
    for (const s of OWASP_MCP_TOP_10) {
      expect(_SIGNATURE_OWASP_TABLE[s.id], `catalog id "${s.id}" is missing from the OWASP pin table`).toBeDefined();
    }
  });

  it("every signature_id literal emitted directly in src/guard/*.ts has an explicit table entry", () => {
    const emitted = emittedSignatureIds();
    expect(emitted.length).toBeGreaterThan(0); // sanity: the scan actually found something
    for (const id of emitted) {
      expect(_SIGNATURE_OWASP_TABLE[id], `emitted signature_id "${id}" is missing from the OWASP pin table`).toBeDefined();
    }
  });
});

describe("owaspPinFor", () => {
  it("an id absent from the table returns unknown, never a fabricated category", () => {
    expect(owaspPinFor("some-future-signature-nobody-has-classified-yet")).toEqual({
      status: "unknown",
      ref: OWASP_MCP_TOP_10_REF,
    });
  });

  it("a pinned catalog id returns its classified category", () => {
    expect(owaspPinFor("owasp-mcp-1-tool-description-injection")).toEqual({
      status: "pinned",
      id: "MCP03",
      ref: OWASP_MCP_TOP_10_REF,
    });
  });

  it("an unpinnable id (guard health, not an attack class) returns unpinnable", () => {
    expect(owaspPinFor("guard-inspection-truncated")).toEqual({
      status: "unpinnable",
      ref: OWASP_MCP_TOP_10_REF,
    });
  });
});

describe("docs/owasp-mcp-mapping.md sync", () => {
  it("the doc is pinned to the same commit this module hardcodes", () => {
    const docPath = path.resolve(GUARD_DIR, "../../docs/owasp-mcp-mapping.md");
    const doc = readFileSync(docPath, "utf-8");
    expect(doc).toContain(OWASP_MCP_TOP_10_REF);
  });
});

describe("owaspPinForScannerType", () => {
  const ALL_TYPES: Finding["type"][] = [
    "secrets",
    "prompt-injection",
    "typosquatting",
    "exfil-args",
    "scanner-error",
    "release-cooldown",
    "install-script",
    "registry-status",
  ];

  it("covers every Finding type with a pinned or unpinnable verdict (never unknown)", () => {
    for (const type of ALL_TYPES) {
      const pin = owaspPinForScannerType(type);
      expect(["pinned", "unpinnable"]).toContain(pin.status);
    }
  });

  it("scanner-error is unpinnable (no relationship in SARIF)", () => {
    expect(owaspPinForScannerType("scanner-error")).toEqual({
      status: "unpinnable",
      ref: OWASP_MCP_TOP_10_REF,
    });
  });

  it("secrets pins to MCP01", () => {
    expect(owaspPinForScannerType("secrets")).toEqual({
      status: "pinned",
      id: "MCP01",
      ref: OWASP_MCP_TOP_10_REF,
    });
  });
});
