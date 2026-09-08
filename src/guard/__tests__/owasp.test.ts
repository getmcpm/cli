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

/**
 * Every signature-id string literal written directly in a non-test file under
 * `src/guard/` — RECURSIVELY (`confine/`, `demo/`, any future subdirectory),
 * and in both shapes the tree actually uses: an inline `signature_id: "<id>"`
 * and the `const <NAME>_SIGNATURE_ID = "<id>"` form the structural detectors
 * (`exfil-params.ts`, `shell-metachar-args.ts`, …) emit through. The first
 * revision of this scan was non-recursive and inline-only, so it saw 14 of the
 * 20 ids the guard can emit and would not have failed for a new detector
 * written the way every existing structural detector is written.
 */
function emittedSignatureIds(): string[] {
  const ids = new Set<string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "__tests__") walk(full);
        continue;
      }
      if (!entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
      const text = readFileSync(full, "utf-8");
      for (const m of text.matchAll(/(?:signature_id:|_SIGNATURE_ID\s*=)\s*"([^"]+)"/g)) {
        const id = m[1];
        if (id !== undefined) ids.add(id);
      }
    }
  };
  walk(GUARD_DIR);
  return [...ids];
}

describe("owaspPinFor — exhaustiveness", () => {
  it("every OWASP_MCP_TOP_10 catalog id has an explicit table entry", () => {
    for (const s of OWASP_MCP_TOP_10) {
      expect(
        Object.hasOwn(_SIGNATURE_OWASP_TABLE, s.id),
        `catalog id "${s.id}" is missing from the OWASP pin table`,
      ).toBe(true);
    }
  });

  it("every signature_id literal emitted directly in src/guard/*.ts has an explicit table entry", () => {
    const emitted = emittedSignatureIds();
    expect(emitted.length).toBeGreaterThan(0); // sanity: the scan actually found something
    // Pins the `_SIGNATURE_ID = "..."` half of the scan: this id appears in the
    // tree ONLY as a const, never as an inline `signature_id:` literal, so an
    // inline-only regex silently drops it (and the five other structural
    // detectors written the same way) while staying green.
    // The RECURSION half is not pinnable by content today — no file under a
    // src/guard subdirectory currently writes either literal shape — so
    // narrowing the walk back to one level survives every test. Named here
    // rather than left to be rediscovered.
    expect(emitted).toContain("exfil-param-in-schema");
    for (const id of emitted) {
      expect(
        Object.hasOwn(_SIGNATURE_OWASP_TABLE, id),
        `emitted signature_id "${id}" is missing from the OWASP pin table`,
      ).toBe(true);
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

  // The table is an object LITERAL, so a bare `TABLE[id]` walks Object.prototype:
  // before the hasOwn guard, `owaspPinFor("toString")` returned
  // `{status:"pinned"}` with NO `id` — a fabricated pin that is not even a valid
  // OwaspPin. Same class as the v0.38.0 `__proto__` fix.
  it.each(["toString", "constructor", "hasOwnProperty", "__proto__", "valueOf"])(
    "an inherited Object.prototype key (%s) is unknown, not a fabricated pin",
    (key) => {
      expect(owaspPinFor(key)).toEqual({ status: "unknown", ref: OWASP_MCP_TOP_10_REF });
    },
  );

  // Every confine spawn-decision event reaches guard-events.jsonl as a
  // signature_id (run-inner.ts `confineGuardEvent`). They are the same
  // guard-health class as `orig-hash-mismatch`, which was already classified;
  // these six were absent from the table and so read "unknown" — "not yet
  // classified" — about the one class the mapping doc says was evaluated.
  it.each([
    "confine-applied",
    "confine-marker-stripped",
    "confine-hash-mismatch",
    "confine-backend-missing",
    "confine-profile-missing",
    "confine-marker-malformed",
  ])("the confine spawn event %s is unpinnable, not unknown", (id) => {
    expect(owaspPinFor(id)).toEqual({ status: "unpinnable", ref: OWASP_MCP_TOP_10_REF });
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
