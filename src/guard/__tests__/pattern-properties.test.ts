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
import { CONFUSABLES, normalizeForMatch } from "../patterns.js";
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

// ASCII letter -> the look-alikes the pipeline promises to fold onto it.
const LOOK_ALIKES: ReadonlyMap<string, readonly string[]> = (() => {
  const m = new Map<string, string[]>();
  for (const [glyph, ascii] of Object.entries(CONFUSABLES)) {
    m.set(ascii, [...(m.get(ascii) ?? []), glyph]);
  }
  return m;
})();

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
// results, tool-call params, and the server-initiated sampling/elicitation path.
const anyString = fc.string({ unit: "binary", maxLength: 200 });
const json = fc.jsonValue({ maxDepth: 6 });
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
        fc.record({ name: anyString, description: anyString, inputSchema: json, annotations: json }),
        { maxLength: 4 },
      ),
    }),
  }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    result: fc.record({
      content: fc.array(fc.record({ type: fc.constant("text"), text: anyString }), { maxLength: 4 }),
      structuredContent: json,
    }),
  }),
  fc.record({
    jsonrpc: fc.constant("2.0" as const),
    id,
    method: fc.constant("tools/call"),
    params: fc.record({ name: anyString, arguments: json }),
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
