/**
 * Property-based checks on the guard's shared match pipeline (fast-check).
 *
 * Two properties, each a real invariant the hand-written suites pin only at a
 * handful of chosen strings:
 *
 * 1. EVASION-INVARIANCE of `normalizeForMatch`. Every detector matches on its
 *    output, so this is the one seam where "the attacker inserted a zero-width
 *    space inside the phrase" (the v0.20.0 bypass, #130) and "the attacker spelled
 *    it with a Cyrillic о" (security #30) are supposed to be erased. Stated
 *    generally: for a printable-ASCII string, ANY interleaving of
 *    `PATTERN_BREAKERS` characters and ANY substitution of letters by their
 *    fullwidth or confusable look-alikes normalizes back to the plain ASCII
 *    string, byte for byte.
 *
 *    The alphabet deliberately excludes combining marks. A breaker placed between
 *    a base letter and U+0301 blocks NFKC composition, so the outputs differ by
 *    one legitimate precomposed-vs-decomposed spelling — irrelevant to the
 *    ASCII-anchored catalog, but it would make the property false and the test
 *    flaky in proportion to how rarely the generator hits it. Idempotence of the
 *    pipeline is NOT asserted for the same reason: NFKC composes a FOLDED `o` with
 *    a following combining mark on the second pass but not the first.
 *
 * 2. TOTALITY of `inspectFrame` over arbitrary JSON. A throw on the relay hot
 *    path is the crash-loop class #130 closed for malformed frames; the inspector
 *    must return a verdict for anything `JSON.parse` can produce, including
 *    `__proto__` keys, deep nesting and non-string leaves in every carrier slot.
 *
 * Both run at fast-check's default 100 cases; a failure prints the seed and the
 * shrunk counterexample, which is the whole point over a fixed fixture list.
 */
import fc from "fast-check";
import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { normalizeForMatch } from "../patterns.js";
import { inspectFrame } from "../inspect-frame.js";

// The spec of what must be stripped, written independently of PATTERN_BREAKERS so
// that removing a class from the source regex fails here rather than silently
// narrowing both. Soft hyphen; ZW space/non-joiner/joiner + LRM/RLM; bidi embeds
// and overrides; word joiner through the deprecated format block; BOM; the
// Unicode TAG block (#31).
const BREAKERS: readonly string[] = [
  ...range(0x00ad, 0x00ad),
  ...range(0x200b, 0x200f),
  ...range(0x202a, 0x202e),
  ...range(0x2060, 0x206f),
  ...range(0xfeff, 0xfeff),
  ...range(0xe0000, 0xe007f),
];

function range(from: number, to: number): string[] {
  const out: string[] = [];
  for (let cp = from; cp <= to; cp++) out.push(String.fromCodePoint(cp));
  return out;
}

const PRINTABLE_ASCII = range(0x20, 0x7e);

// The spec of which look-alikes fold to which ASCII letter (TR39 skeleton,
// Cyrillic + Greek scope, security #30). Deliberately NOT imported from
// patterns.ts: a generator built from the code's own CONFUSABLES table stops
// producing a glyph the moment the code stops folding it, so deleting a mapping
// would leave this suite green — measured, not supposed (mutation M2 survived
// exactly that way before this list was made spec-side).
const LOOK_ALIKES: ReadonlyMap<string, readonly string[]> = new Map([
  ["a", ["\u0430", "\u03b1"]], ["A", ["\u0410", "\u0391"]],
  ["e", ["\u0435", "\u03b5"]], ["E", ["\u0415", "\u0395"]],
  ["o", ["\u043e", "\u03bf"]], ["O", ["\u041e", "\u039f"]],
  ["p", ["\u0440", "\u03c1"]], ["P", ["\u0420", "\u03a1"]],
  ["c", ["\u0441"]],           ["C", ["\u0421"]],
  ["y", ["\u0443"]],           ["Y", ["\u0423", "\u03a5"]],
  ["x", ["\u0445", "\u03c7"]], ["X", ["\u0425", "\u03a7"]],
  ["i", ["\u0456", "\u03b9"]], ["I", ["\u0406", "\u0399"]],
  ["j", ["\u0458"]],           ["J", ["\u0408"]],
  ["d", ["\u0501"]],           ["q", ["\u051b"]],
  ["s", ["\u0455"]],           ["S", ["\u0405"]],
  ["h", ["\u04bb"]],           ["H", ["\u0397"]],
  ["v", ["\u03bd"]],           ["N", ["\u039d"]],
  ["t", ["\u03c4"]],           ["T", ["\u03a4"]],
  ["u", ["\u03c5"]],           ["k", ["\u03ba"]], ["K", ["\u039a"]],
  ["n", ["\u03b7"]],
]);

// U+FF01..U+FF5E are the fullwidth forms of U+0021..U+007E; NFKC maps them back.
function fullwidth(ch: string): string {
  const cp = ch.codePointAt(0)!;
  return cp >= 0x21 && cp <= 0x7e ? String.fromCodePoint(cp + 0xfee0) : ch;
}

const disguisedChar = fc.record({
  ch: fc.constantFrom(...PRINTABLE_ASCII),
  form: fc.constantFrom("plain", "fullwidth", "confusable"),
  pick: fc.nat(),
  pad: fc.array(fc.constantFrom(...BREAKERS), { maxLength: 2 }),
});

function disguise(c: { ch: string; form: string; pick: number }): string {
  if (c.form === "fullwidth") return fullwidth(c.ch);
  if (c.form === "confusable") {
    const alts = LOOK_ALIKES.get(c.ch);
    if (alts && alts.length > 0) return alts[c.pick % alts.length]!;
  }
  return c.ch;
}

describe("normalizeForMatch — evasion-invariance", () => {
  test("breaker interleaving + look-alike substitution normalize to the plain ASCII string", () => {
    fc.assert(
      fc.property(
        fc.array(disguisedChar, { minLength: 1, maxLength: 64 }),
        fc.array(fc.constantFrom(...BREAKERS), { maxLength: 2 }),
        (chars, trailing) => {
          const plain = chars.map((c) => c.ch).join("");
          const evasive = chars.map((c) => c.pad.join("") + disguise(c)).join("") + trailing.join("");
          expect(normalizeForMatch(evasive)).toBe(plain);
        },
      ),
    );
  });

  test("plain printable ASCII is a fixed point", () => {
    fc.assert(
      fc.property(fc.string({ unit: fc.constantFrom(...PRINTABLE_ASCII) }), (s) => {
        expect(normalizeForMatch(s)).toBe(s);
      }),
    );
  });
});

// Arbitrary JSON, plus the frame shapes that actually route into a carrier so the
// detectors run rather than the routing miss: tools/list definitions, tool-call
// results, tool-call params, and the server-initiated sampling/elicitation path —
// each with its string slots sometimes holding the wrong type.
const anyString = fc.string({ unit: "binary", maxLength: 200 });
const json = fc.jsonValue({ maxDepth: 6 });
// Every slot the routing reads as a string also gets non-strings: a server that
// returns `tools: [{name: 42}]` or `content: [7]` must be inspected, not crash.
const stringOrJson = fc.oneof(anyString, json);
const id = fc.oneof(fc.integer(), fc.string());

const frame: fc.Arbitrary<JSONRPCMessage> = fc.oneof(
  fc.record({ jsonrpc: fc.constant("2.0" as const), id, result: json }),
  fc.record({ jsonrpc: fc.constant("2.0" as const), id, method: anyString, params: json }),
  fc.record({ jsonrpc: fc.constant("2.0" as const), method: anyString, params: json }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    result: fc.record({
      tools: fc.array(
        fc.oneof(
          json,
          fc.record({ name: stringOrJson, description: stringOrJson, inputSchema: json, annotations: json }),
        ),
        { maxLength: 4 },
      ),
    }),
  }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    result: fc.record({
      content: fc.array(fc.oneof(json, fc.record({ type: fc.constant("text"), text: stringOrJson })), { maxLength: 4 }),
      structuredContent: json,
    }),
  }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    method: fc.constant("tools/call"),
    params: fc.record({ name: stringOrJson, arguments: json }),
  }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    method: fc.constantFrom("sampling/createMessage", "elicitation/create"),
    params: json,
  }),
) as fc.Arbitrary<JSONRPCMessage>;

describe("inspectFrame — total over arbitrary frames", () => {
  test("returns a verdict, never throws", () => {
    fc.assert(
      fc.property(frame, (msg) => {
        const r = inspectFrame(msg);
        expect(["pass", "warn", "block"]).toContain(r.action);
        expect(Array.isArray(r.findings)).toBe(true);
      }),
    );
  });
});

// The shapes the totality property found on its first widened run, kept as a
// fixed table so the fix is pinned by a named case and not only by a seed.
describe("inspectFrame — malformed server arrays (found by the property above)", () => {
  test.each([
    ["tools: [null]", { tools: [null] }],
    ["tools: {} (not an array)", { tools: { a: 1 } }],
    ["tools: [7, 'x']", { tools: [7, "x"] }],
    ["contents: [null]", { contents: [null] }],
    ["messages: [null]", { messages: [null] }],
  ])("%s is a verdict, not a throw", (_label, result) => {
    const r = inspectFrame({ jsonrpc: "2.0", id: 1, result } as JSONRPCMessage);
    expect(["pass", "warn", "block"]).toContain(r.action);
  });
});
