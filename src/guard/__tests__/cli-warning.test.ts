/**
 * Regression test for the `guard disable` placeholder-warning key rendering.
 *
 * The warning previously used `keys.map(sanitize)`, which passes the array
 * index as sanitizeForTerminal's `maxLen` — truncating the first key to "…",
 * the second to one char, etc. formatAffectedKeys wraps the call so each key
 * is sanitized on its own.
 */

import { describe, it, expect } from "vitest";
import { formatAffectedKeys } from "../cli.js";

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
