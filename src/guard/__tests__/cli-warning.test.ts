/**
 * Regression test for the `guard disable` placeholder-warning key rendering.
 *
 * The warning previously used `keys.map(sanitize)`, which passes the array
 * index as sanitizeForTerminal's `maxLen` — truncating the first key to "…",
 * the second to one char, etc. formatAffectedKeys wraps the call so each key
 * is sanitized on its own.
 */

import { describe, it, expect } from "vitest";
import { formatAffectedKeys, printUnguardedWarning } from "../cli.js";
import type { EnableDisableSummary } from "../orchestrator.js";

describe("formatAffectedKeys (guard disable warning)", () => {
  it("renders the real key names, not ellipsis (the .map(sanitize) bug)", () => {
    expect(formatAffectedKeys(["TOKEN", "API"])).toBe("TOKEN, API");
  });

  it("renders a single key unchanged", () => {
    expect(formatAffectedKeys(["GITHUB_TOKEN"])).toBe("GITHUB_TOKEN");
  });

  it("still truncates a genuinely long key via sanitize's default maxLen", () => {
    const out = formatAffectedKeys(["K".repeat(300)]);
    expect(out.endsWith("…")).toBe(true);
    expect(out.length).toBeLessThan(300);
  });
});

// ---------------------------------------------------------------------------
// printUnguardedWarning — delta listing (H9-FP-1) + chalk-not-raw-ANSI (nit)
// ---------------------------------------------------------------------------

function summaryWithUnguarded(names: readonly string[]): EnableDisableSummary {
  return {
    action: "enable",
    clients: [
      {
        clientId: "cursor",
        servers: names.map((name) => ({ name, status: "unguarded" as const })),
      },
    ],
    totalChanged: 0,
    totalSkipped: 0,
    totalUnguarded: names.length,
    errors: 0,
  };
}

function capture(): { write: (s: string) => void; text: () => string } {
  let buf = "";
  return { write: (s) => (buf += s), text: () => buf };
}

describe("printUnguardedWarning (guard enable warn-once)", () => {
  it("lists ONLY the newly-consented delta, not already-consented servers", () => {
    const out = capture();
    // A,B already consented; C is the new risk.
    printUnguardedWarning(summaryWithUnguarded(["A", "B", "C"]), ["A", "B"], out);
    const text = out.text();
    expect(text).toContain("⚠ C");
    // A and B must NOT be re-listed as new risks.
    expect(text).not.toContain("⚠ A");
    expect(text).not.toContain("⚠ B");
    // …but their count is surfaced quietly.
    expect(text).toContain("+2 previously consented");
    expect(text).toContain("does NOT add protection");
  });

  it("uses chalk (suppressed in non-TTY), not raw ANSI escape literals", () => {
    const out = capture();
    printUnguardedWarning(summaryWithUnguarded(["X"]), [], out);
    // chalk respects NO_COLOR / non-TTY: under vitest (no TTY) no escapes leak.
    expect(out.text()).not.toContain("\x1b[33m");
    expect(out.text()).toContain("⚠ X");
  });

  it("stays quiet (no full warning) when the consented set is unchanged", () => {
    const out = capture();
    printUnguardedWarning(summaryWithUnguarded(["A"]), ["A"], out);
    expect(out.text()).not.toContain("does NOT add protection");
    expect(out.text()).toContain("previously consented");
  });
});
