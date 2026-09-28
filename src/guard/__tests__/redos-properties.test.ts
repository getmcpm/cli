/**
 * Equivalence checks for the three ReDoS fixes in `signatures.ts` (#113).
 *
 * Each of these signatures had its regex source rewritten for performance
 * (see the comments beside `generic-bearer-token-disclosure` and
 * `renderer-code-execution-in-response`). The OLD (slow) regex is kept here,
 * verbatim, as a test-only oracle, and fast-check drives random inputs built
 * from the alphabet each pattern actually cares about — never full 64KB
 * inputs (the old regex is exponential there by construction; that's the bug
 * being fixed), bounded instead to a few hundred characters so the oracle
 * itself stays fast and the search explores many small, adversarial shapes.
 *
 * The property is exact equivalence of `RegExp#exec`: same null-vs-match
 * verdict, and when both match, the same `match[0]` and `match.index`.
 */
import fc from "fast-check";
import { describe, expect, test } from "vitest";

// ---------------------------------------------------------------------------
// generic-bearer-token-disclosure
// ---------------------------------------------------------------------------

const C = "[A-Za-z0-9._~+/=-]";
// OLD: signatures.ts before #113 — O(n^2) on an adversarial token (see
// signature-perf.test.ts for the wall-clock regression this replaced).
const BEARER_OLD = new RegExp(`Bearer\\s+(?=${C}{20,})${C}*[0-9]${C}*(?![${C.slice(1, -1)}])(?<!\\.\\.\\.)`);
// NEW: the shipped pattern in signatures.ts (kept in sync by hand; a mismatch
// here would mean this test is no longer testing what ships).
const BEARER_NEW = /Bearer\s+(?=([A-Za-z0-9._~+/=-]{20,}))\1(?<=[0-9][A-Za-z0-9._~+/=-]*)(?<!\.\.\.)/;

// The alphabet the comment on the signature itself calls out: whitespace, the
// token class, digits (weighted up — a "does the run contain a digit"
// property is only interesting when digits are common), literal "...", the
// single Unicode ellipsis (pre-NFKC-fold — the signature runs post-fold in
// production, but the regex itself must also agree with its oracle on the
// raw character), and ordinary prose words so "Bearer" appears embedded in
// realistic-looking text too.
const bearerAlphabetChar = fc.constantFrom(
  ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  ..."0123456789",
  ..."0123456789", // weight digits up
  ".",
  "_",
  "~",
  "+",
  "/",
  "=",
  "-",
  " ",
  "\n",
  "\t",
);
const bearerFragment = fc.oneof(
  fc.string({ unit: bearerAlphabetChar, minLength: 0, maxLength: 40 }),
  fc.constant("Bearer"),
  fc.constant("..."),
  fc.constant("…"), // single-char ellipsis; NFKC-folds to "..." upstream of this regex
  fc.constant(" the quick brown fox "),
  fc.constant("token"),
);
const bearerInput = fc
  .array(bearerFragment, { minLength: 0, maxLength: 8 })
  .map((parts) => parts.join("").slice(0, 300));

describe("generic-bearer-token-disclosure: new pattern matches the old one", () => {
  test("same null/match[0]/index on inputs built from Bearer+token-class+digit+ellipsis alphabet", () => {
    fc.assert(
      fc.property(bearerInput, (s) => {
        const oldM = BEARER_OLD.exec(s);
        const newM = BEARER_NEW.exec(s);
        if (oldM === null || newM === null) {
          expect(newM).toBe(oldM);
        } else {
          expect(newM[0]).toBe(oldM[0]);
          expect(newM.index).toBe(oldM.index);
        }
      }),
      { numRuns: 3000 },
    );
  });

  // Fixed points pinned individually: this is the exact FP the signature was
  // built to suppress, and a property test over a random alphabet is not
  // guaranteed to reconstruct it by chance.
  test("truncation-marker suppression case matches the old pattern (both null)", () => {
    const s = "Bearer eyJhbGciOiJIUzI1NiIs...";
    expect(BEARER_NEW.exec(s)).toBe(null);
    expect(BEARER_OLD.exec(s)).toBe(null);
  });
});

// ---------------------------------------------------------------------------
// renderer-code-execution-in-response
// ---------------------------------------------------------------------------

const BRIDGE = "electron\\s*\\.\\s*mcp\\s*\\.\\s*(?:activate|addServer)\\s*\\(";

function attrPattern(cap: number | null): RegExp {
  const q = cap === null ? "*" : `{0,${cap}}`;
  const qLazy = cap === null ? "*?" : `{0,${cap}}?`;
  return new RegExp(
    `<[a-zA-Z][\\w-]*\\b[^<>]${qLazy}\\son[a-z]+\\s*=\\s*` +
      `(?:"(?=[^"]${q}(?:${BRIDGE}))[^"]${q}"` +
      `|'(?=[^']${q}(?:${BRIDGE}))[^']${q}'` +
      `|(?!["'])(?=[^\\s>]${q}(?:${BRIDGE}))[^\\s>]${q})` +
      `[^<>]${q}>`,
    "i",
  );
}
// OLD: unbounded quantifiers (signatures.ts before #113).
const ATTR_OLD = attrPattern(null);
// NEW: the shipped {0,2000}-capped pattern. Bounding only changes behaviour
// once a single tag's scan region exceeds 2000 chars, which the property test
// below keeps inputs well short of (<=300 chars total), so on this alphabet
// old and new are expected to agree exactly.
const ATTR_NEW = attrPattern(2000);

function scriptPattern(iterCap: number | null): RegExp {
  const q = iterCap === null ? "*" : `{0,${iterCap}}`;
  return new RegExp(
    `<script\\b(?:"[^"]*"|'[^']*'|[^>"'])${q}>(?:(?!</script>)[\\s\\S]){0,2000}?(?:${BRIDGE})`,
    "i",
  );
}
// OLD: unbounded alternation (signatures.ts before #113). Character class is
// UNCHANGED from shipped — an earlier draft of the fix excluded '<' from the
// bare alternative, but that changes real matching behaviour (a real HTML
// tokenizer, and this regex, both treat a stray '<' inside a tag's attribute
// region as the start of a bogus attribute name and keep scanning for the
// tag's real '>' — see the signatures.ts comment), so it is deliberately
// identical here.
const SCRIPT_OLD = scriptPattern(null);
// NEW: the shipped iteration-count-bounded pattern ({0,500} repetitions of
// the alternation group, not a character-count bound — a single quoted-value
// iteration can still be arbitrarily long).
const SCRIPT_NEW = scriptPattern(500);

// Alphabet: tag punctuation, the literal bridge call (and near-misses of it),
// quotes, event-handler-shaped words, and ordinary letters/space so a tag can
// appear embedded in prose.
const rendererFragment = fc.oneof(
  fc.constant("<a"),
  fc.constant("<img"),
  fc.constant("<script"),
  fc.constant("<script "),
  fc.constant("</script>"),
  fc.constant(" on"),
  fc.constant("onerror"),
  fc.constant("onclick"),
  fc.constant("onx"),
  fc.constant("="),
  fc.constant('"'),
  fc.constant("'"),
  fc.constant(" "),
  fc.constant(">"),
  fc.constant("<"),
  fc.constant("electron.mcp.activate("),
  fc.constant("electron.mcp.addServer("),
  fc.constant("electron.mcp."), // near-miss, no call
  fc.constant("electron"),
  fc.string({
    unit: fc.constantFrom(..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"),
    minLength: 0,
    maxLength: 15,
  }),
);
const rendererInput = fc
  .array(rendererFragment, { minLength: 0, maxLength: 12 })
  .map((parts) => parts.join("").slice(0, 300));

describe("renderer-code-execution-in-response: attribute pattern (shape 1) matches the old one", () => {
  test("same null/match[0]/index on the tag/attribute alphabet, capped well under the 2000-char bound", () => {
    fc.assert(
      fc.property(rendererInput, (s) => {
        const oldM = ATTR_OLD.exec(s);
        const newM = ATTR_NEW.exec(s);
        if (oldM === null || newM === null) {
          expect(newM).toBe(oldM);
        } else {
          expect(newM[0]).toBe(oldM[0]);
          expect(newM.index).toBe(oldM.index);
        }
      }),
      { numRuns: 3000 },
    );
  });
});

describe("renderer-code-execution-in-response: <script> tag-open pattern (shape 2) matches the old one", () => {
  // Unlike the attribute pattern, this fix changes ONLY the alternation's
  // iteration-count ceiling (500), not its character class or per-iteration
  // length — a single quoted-value iteration is still unbounded. Since every
  // generated input is capped at 300 characters and each iteration consumes
  // at least one character, the 500-iteration ceiling can never actually be
  // reached here, so old and new are expected to be BYTE-IDENTICAL (not
  // merely "equivalent modulo a documented gap") across this whole alphabet —
  // a stronger result than the attribute pattern's, and the reason no
  // "intentional divergence" case is needed below (contrast with the earlier,
  // rejected `<`-exclusion draft, which the comment in signatures.ts and the
  // git history of this file record as changing real behaviour).
  test("same null/match[0]/index on the tag/script alphabet", () => {
    fc.assert(
      fc.property(rendererInput, (s) => {
        const oldM = SCRIPT_OLD.exec(s);
        const newM = SCRIPT_NEW.exec(s);
        if (oldM === null || newM === null) {
          expect(newM).toBe(oldM);
        } else {
          expect(newM[0]).toBe(oldM[0]);
          expect(newM.index).toBe(oldM.index);
        }
      }),
      { numRuns: 3000 },
    );
  });

  // Pinned individually: the browser-accurate "crosses a stray '<'" behaviour
  // this fix deliberately preserves (see the signatures.ts comment) — both
  // patterns must still match this exact shape.
  test("preserves the browser-accurate 'crosses a stray unquoted <' behaviour", () => {
    const s = "<script </script>electron.mcp.addServer(";
    expect(SCRIPT_OLD.exec(s)?.[0]).toBe(s);
    expect(SCRIPT_NEW.exec(s)?.[0]).toBe(s);
  });

  // The one documented, accepted gap: more than 500 alternation iterations
  // (roughly 60+ short quoted attributes) before the real tag close is missed
  // by the capped pattern but still caught by the old, unbounded one.
  test("documented gap: more than 500 alternation iterations before the bridge call is missed", () => {
    let manyAttrs = "<script";
    for (let i = 0; i < 60; i++) manyAttrs += ` data${i}="v${i}"`;
    manyAttrs += "> electron.mcp.activate(1)</script>";
    expect(SCRIPT_OLD.exec(manyAttrs)).not.toBe(null);
    expect(SCRIPT_NEW.exec(manyAttrs)).toBe(null);
  });
});
