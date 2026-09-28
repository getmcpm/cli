/**
 * Equivalence checks for the ReDoS rewrites in `signatures.ts` (#113).
 *
 * Each OLD regex (main before #113, which backtracked super-linearly) is kept
 * here verbatim as a test-only oracle and compared, over fast-check inputs,
 * against the pattern that SHIPS — read from the catalog, never a hand copy,
 * so an edit to `signatures.ts` is what these tests judge. Inputs stay short
 * (the oracles are quadratic) and are built from the fragments each pattern
 * cares about. Each property also asserts that the oracle matched a fair share
 * of the inputs, so a generator that stops producing matches fails loudly
 * instead of certifying nothing.
 */
import fc from "fast-check";
import { describe, expect, test } from "vitest";
import { OWASP_MCP_TOP_10 } from "../signatures.js";

function shipped(id: string, index: number): RegExp {
  const sig = OWASP_MCP_TOP_10.find((s) => s.id === id);
  const re = sig?.patterns[index];
  if (re === undefined) throw new Error(`no pattern ${id}[${index}]`);
  return re;
}

const joined = (frag: fc.Arbitrary<string>, maxLength: number): fc.Arbitrary<string> =>
  fc.array(frag, { maxLength }).map((parts) => parts.join(""));

/** Asserts exact exec agreement; returns how many inputs the oracle matched. */
function assertSameExec(oracle: RegExp, actual: RegExp, input: fc.Arbitrary<string>, numRuns: number): number {
  let matched = 0;
  fc.assert(
    fc.property(input, (s) => {
      const o = oracle.exec(s);
      const a = actual.exec(s);
      if (o !== null) matched++;
      expect(a?.[0]).toBe(o?.[0]);
      expect(a?.index).toBe(o?.index);
    }),
    { numRuns },
  );
  return matched;
}

// ---------------------------------------------------------------------------
// generic-bearer-token-disclosure
// ---------------------------------------------------------------------------

const C = "[A-Za-z0-9._~+/=-]";
const BEARER_OLD = new RegExp(`Bearer\\s+(?=${C}{20,})${C}*[0-9]${C}*(?!${C})(?<!\\.\\.\\.)`);
const BEARER = shipped("generic-bearer-token-disclosure", 0);

const bearerChar = fc.constantFrom(
  ..."AZaz09._~+/=-",
  ..."0123456789",
  " ",
  "\t",
  "\n",
  " ",
  "　",
  "@",
  "é",
);
const bearerInput = joined(
  fc.oneof(
    fc.string({ unit: bearerChar, maxLength: 30 }),
    fc.constantFrom("Bearer", "Bearer ", "Bearer ", "...", "..", "…", "a".repeat(18), "a".repeat(19), "1", "ab12cd34ef56gh78ij90"),
  ),
  10,
);

describe("generic-bearer-token-disclosure: shipped pattern matches the old one", () => {
  test("same match[0] and index", () => {
    const matched = assertSameExec(BEARER_OLD, BEARER, bearerInput, 5000);
    expect(matched).toBeGreaterThan(50);
  });

  test("the truncation-marker case still passes, a run of exactly 20 still matches", () => {
    expect(BEARER.exec("Bearer eyJhbGciOiJIUzI1NiIs...")).toBe(null);
    expect(BEARER.exec(`Bearer ${"a".repeat(19)}1`)?.[0]).toBe(`Bearer ${"a".repeat(19)}1`);
    expect(BEARER.exec(`Bearer ${"a".repeat(18)}1`)).toBe(null);
  });
});

// ---------------------------------------------------------------------------
// renderer-code-execution-in-response
// ---------------------------------------------------------------------------

const BRIDGE = "electron\\s*\\.\\s*mcp\\s*\\.\\s*(?:activate|addServer)\\s*\\(";
const ATTR_OLD = new RegExp(
  "<[a-zA-Z][\\w-]*\\b[^<>]*?\\son[a-z]+\\s*=\\s*" +
    `(?:"(?=[^"]*(?:${BRIDGE}))[^"]*"` +
    `|'(?=[^']*(?:${BRIDGE}))[^']*'` +
    `|(?!["'])(?=[^\\s>]*(?:${BRIDGE}))[^\\s>]*)` +
    "[^<>]*>",
  "i",
);
const SCRIPT_OLD = new RegExp(
  `<script\\b(?:"[^"]*"|'[^']*'|[^>"'])*>(?:(?!</script>)[\\s\\S]){0,2000}?(?:${BRIDGE})`,
  "i",
);
const ATTR = shipped("renderer-code-execution-in-response", 0);
const SCRIPT = shipped("renderer-code-execution-in-response", 1);

// Random tokens alone almost never assemble a whole tag (a first cut matched 0
// of 5000), so whole tags are generated too, with values that carry the bridge
// call, stray `<`/`>`/quotes and nested `<script`, and are mixed with the noise.
const piece = fc.constantFrom(
  "electron.mcp.activate(", "electron . mcp . addServer (", "electron.mcp.", "x", " ", ";",
  "<", ">", '"', "'", "<script", "<script ", "</script>", "a-",
);
const pieces = joined(piece, 5);
const attr = fc
  .tuple(fc.constantFrom(" on", " onclick", "\tonerror", " x", " data-y"), fc.constantFrom("=", " = "), fc.constantFrom('"', "'", ""), pieces)
  .map(([name, eq, q, v]) => `${name}${eq}${q}${v}${q}`);
const tag = fc
  .tuple(fc.constantFrom("<a", "<A-", "<img", "<a-b-", "<script", "<SCRIPT", "<scripts"), joined(attr, 4), fc.constantFrom(">", " >", "", "<"), pieces)
  .map((parts) => parts.join(""));
const rendererInput = joined(fc.oneof(tag, piece, fc.string({ unit: fc.constantFrom(..."abxyz019_-;:/()"), maxLength: 8 })), 6);

describe("renderer-code-execution-in-response: attribute pattern (shape 1) matches the old one", () => {
  test("same match[0] and index", () => {
    const matched = assertSameExec(ATTR_OLD, ATTR, rendererInput, 5000);
    expect(matched).toBeGreaterThan(100);
  });
});

describe("renderer-code-execution-in-response: <script> pattern (shape 2) matches the old one", () => {
  // A bare `<script` inside a tag now ends that start's scan and a later start
  // takes over, so the reported match can START later than the old one's, and
  // then end elsewhere too (see signatures.ts). Whether it matches never changes.
  test("same verdict; the match never starts earlier", () => {
    let matched = 0;
    let laterStart = 0;
    fc.assert(
      fc.property(rendererInput, (s) => {
        const o = SCRIPT_OLD.exec(s);
        const a = SCRIPT.exec(s);
        expect(a === null).toBe(o === null);
        if (o === null || a === null) return;
        matched++;
        if (a.index !== o.index) laterStart++;
        expect(a.index).toBeGreaterThanOrEqual(o.index);
      }),
      { numRuns: 5000 },
    );
    expect(matched).toBeGreaterThan(100);
    expect(laterStart).toBeGreaterThan(20);
  });

  test("a stray `<` that is not `<script` still continues the scan, as a browser does", () => {
    const s = "<script </x>electron.mcp.addServer(";
    expect(SCRIPT_OLD.exec(s)?.[0]).toBe(s);
    expect(SCRIPT.exec(s)?.[0]).toBe(s);
  });
});

// A cap on the scans would bound the cost but drop every tag longer than the
// cap, which the old patterns caught. Pinned at sizes a cap would have to
// exceed, so capping again turns these red.
describe("renderer-code-execution-in-response: long tags are still caught (#113)", () => {
  const B = "electron.mcp.activate(1)";
  test.each([
    ["5000 spaces inside <script", `<script${" ".repeat(5000)}>${B}</script>`],
    ["a 5000-char unquoted <script> attribute", `<script data-x=${"a".repeat(5000)}>${B}</script>`],
    ["600 quoted <script> attributes", `<script${' x="y"'.repeat(600)}>${B}</script>`],
    ["5000 spaces before the handler", `<a${" ".repeat(5000)} onclick="${B}">x</a>`],
    ["a 5000-char handler body after the call", `<a onclick="${B};${"x;".repeat(2500)}">x</a>`],
    ["5000 chars of attributes after the handler", `<a onclick="${B}" style="${"a:b;".repeat(1250)}">x</a>`],
  ])("%s", (_name, s) => {
    const re = s.startsWith("<script") ? SCRIPT : ATTR;
    expect(re.exec(s)).not.toBe(null);
  });
});
