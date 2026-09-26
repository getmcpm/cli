/**
 * #109 — `canonicalStringify` must be byte-identical to
 * `JSON.stringify(value, replacer)` for the replacer `hashLeaf` has always
 * used, for every value that can reach it. See `canonical-json.ts`'s module
 * doc for why: a schema-side hash mismatch is a hard BLOCK of the whole
 * `tools/list`, so any divergence here is a false drift finding on every
 * pin written before this fix.
 *
 * Three layers, each catching a different class of divergence:
 *   1. GOLDEN VECTORS — hardcoded sha256 hex captured from the SHIPPED
 *      v0.42.3 `hashLeaf`/`replacerFor` (verbatim from `origin/main`, see
 *      `oldHashToolDefinition` below), asserted against the live
 *      `hashToolDefinition` export (i.e. the real pins.ts → canonical-json.ts
 *      wiring), for the traps this rewrite is most likely to get wrong.
 *   2. DIFFERENTIAL FUZZ — `canonicalStringify` vs real
 *      `JSON.stringify(v, replacer)`, all three replacer forms, over
 *      arbitrary JSON-shaped values (fast-check) including a key/string
 *      arbitrary biased toward the traps above, plus values round-tripped
 *      through `JSON.parse` so non-finite-after-overflow shapes appear.
 *   3. DEEP NESTING — 10,000+ levels (arrays, objects, alternating): no
 *      throw, and the output is byte-identical to a structurally
 *      hand-computed string (never derived via a second JSON.stringify call,
 *      which would just re-hit the same RangeError this file exists to fix).
 */

import { createHash } from "node:crypto";
import fc from "fast-check";
import { describe, expect, test } from "vitest";
import { MAX_DEPTH, canonicalStringify, type JsonReplacer } from "../canonical-json.js";
import { hashToolDefinition } from "../pins.js";

// ---------------------------------------------------------------------------
// Oracle: pins.ts's replacerFor, extracted VERBATIM from
// `git show origin/main:src/guard/pins.ts` (unchanged by this fix — #109
// only replaces the JSON.stringify call inside hashLeaf, not the replacer
// itself). Used ONLY as a differential-testing oracle against real,
// recursive JSON.stringify — never imported by production code.
// ---------------------------------------------------------------------------
function oracleReplacerFor(form: "NFC" | "NFD" | null): JsonReplacer {
  const fold = form === null ? (s: string) => s : (s: string) => s.normalize(form);
  return function canonicalReplacer(_key: string, value: unknown): unknown {
    if (typeof value === "string") return fold(value);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    const injective = new Set(keys.map(fold)).size === keys.length;
    const emit = injective ? fold : (k: string) => k;
    const sorted: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, raw] of keys.map((k) => [emit(k), k] as const).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
      sorted[key] = obj[raw];
    }
    return sorted;
  };
}
const oracleNFC = oracleReplacerFor("NFC");

function sha256(canonical: string): string {
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/** Reproduces the SHIPPED v0.42.3 hashToolDefinition exactly (recursive JSON.stringify + oracle replacer). */
function oldHashToolDefinition(schema: unknown): string {
  const leaves = { description: "", schema, annotations: null };
  return sha256(JSON.stringify(leaves, oracleNFC));
}

// ---------------------------------------------------------------------------
// 1. GOLDEN VECTORS
// ---------------------------------------------------------------------------

describe("GOLDEN VECTORS: byte-identical to shipped v0.42.3 hashToolDefinition", () => {
  const cases: Record<string, unknown> = {
    "integer-like keys mixed with names": { "10": 1, "2": 2, name: "x", "0": 0 },
    "__proto__ key": JSON.parse('{"a":1,"__proto__":{"polluted":true}}'),
    "NFD vs NFC keys (non-injective collision)": (() => {
      const NFD = "café"; // café decomposed
      const NFC = "café"; // café composed
      const o: Record<string, number> = {};
      o[NFD] = 1;
      o[NFC] = 2;
      return o;
    })(),
    "lone surrogates": { s: "a\ud800b\udc00c𐀀d" },
    "control chars": { s: "\u0000\u0001\b\f\n\r\t\u001f" },
    "-0": { z: -0, arr: [-0] },
    "1e400 (Infinity after JSON.parse)": JSON.parse('{"n":1e400,"neg":-1e400}'),
    "empty object/array": { e: {}, a: [] },
    "mixed nesting": { a: [1, { b: [2, 3, { c: null }] }], d: [[[]]] },
  };

  // Precondition: the oracle (this test file's copy) really does reproduce
  // shipped v0.42.3 — anchors the hardcoded hex below to something other than
  // "whatever this test file's own oracle happens to compute".
  const golden: Record<string, string> = {
    "integer-like keys mixed with names": "sha256:1ae863ef60e33ce39eae5e1d45b7f55be4d6f0057fbd475a8cb19ea32a593d6c",
    "__proto__ key": "sha256:f5f70df79688b19ac658cf6b76a9549b6f4d9837cd53b40d979e7ad962c961a0",
    "NFD vs NFC keys (non-injective collision)": "sha256:c75b857ccb8da296b4e9395eca2c484504e22c4b051572050f69f0ff020c1c5a",
    "lone surrogates": "sha256:04ad1da75bdd892faa0c7dff1ec652e4095b8284e5f0671f2a9cca3ae3a3bd2a",
    "control chars": "sha256:4b2e48e0b8d3d665c5237c21b9296b8a302e1ec49ba679897007eb1d4a6fda7e",
    "-0": "sha256:74381a6fb6b7a16e9018b02a8916c5cd8571124c9790d61af7f083f3fe965b87",
    "1e400 (Infinity after JSON.parse)": "sha256:ce5eafc8e1a8e0aaa65a24b887ef6caccf291e4d593a181d0a69602a667410c4",
    "empty object/array": "sha256:05e917232c0a1e049bd4cf14771123f9817575f9e0fff4488290e9cf85489d52",
    "mixed nesting": "sha256:4dca42d5b46aa69788ea2c9c28179ec6e934c1886ce65b689274c8f97a69286e",
  };

  for (const [name, schema] of Object.entries(cases)) {
    test(`oracle self-check: ${name}`, () => {
      expect(oldHashToolDefinition(schema)).toBe(golden[name]);
    });
    test(`live hashToolDefinition matches golden: ${name}`, () => {
      expect(hashToolDefinition({ schema })).toBe(golden[name]);
    });
  }
});

// ---------------------------------------------------------------------------
// 2. DIFFERENTIAL FUZZ vs real JSON.stringify(v, replacer)
// ---------------------------------------------------------------------------

// Biased toward the traps: integer-like strings, __proto__/constructor,
// combining marks + surrogates (via the 'binary' unit, which emits raw
// UTF-16 code units without pairing surrogates).
const biasedKey = fc.oneof(
  { weight: 3, arbitrary: fc.constantFrom("__proto__", "constructor", "toString", "0", "1", "2", "10", "-0", "") },
  { weight: 2, arbitrary: fc.string({ maxLength: 5 }) },
  { weight: 2, arbitrary: fc.string({ unit: "binary", maxLength: 5 }) },
);
const biasedString = fc.oneof(
  { weight: 2, arbitrary: fc.string({ unit: "binary", maxLength: 8 }) },
  { weight: 1, arbitrary: fc.constantFrom("q̣̇", "q̣̇", "Å", "Å", "ﬁ", "fi") },
  { weight: 2, arbitrary: fc.string({ maxLength: 8 }) },
);

const { jsonValue } = fc.letrec((tie) => ({
  jsonValue: fc.oneof(
    { depthSize: "small" },
    fc.constant(null),
    fc.boolean(),
    fc.oneof(fc.integer(), fc.double({ noNaN: true }), fc.constantFrom(-0, 0)),
    biasedString,
    fc.array(tie("jsonValue") as fc.Arbitrary<unknown>, { maxLength: 4 }),
    fc.dictionary(biasedKey, tie("jsonValue") as fc.Arbitrary<unknown>, { maxKeys: 4 }),
  ),
})) as { jsonValue: fc.Arbitrary<unknown> };

const replacerForm = fc.constantFrom<"NFC" | "NFD" | null>("NFC", "NFD", null);

describe("differential fuzz: canonicalStringify(v, r) === JSON.stringify(v, r)", () => {
  test("arbitrary JSON-shaped values, all three replacer forms", () => {
    fc.assert(
      fc.property(jsonValue, replacerForm, (value, form) => {
        const replacer = oracleReplacerFor(form);
        const expected = JSON.stringify(value, replacer);
        const actual = canonicalStringify(value, replacer);
        expect(actual).toBe(expected);
      }),
      { numRuns: 2000 },
    );
  });

  test("JSON.parse(fc.json()) round-trip, all three replacer forms (surfaces -0/Infinity-after-overflow shapes)", () => {
    fc.assert(
      fc.property(fc.json(), replacerForm, (text, form) => {
        const value: unknown = JSON.parse(text);
        const replacer = oracleReplacerFor(form);
        expect(canonicalStringify(value, replacer)).toBe(JSON.stringify(value, replacer));
      }),
      { numRuns: 1000 },
    );
  });
});

// ---------------------------------------------------------------------------
// 3. DEEP NESTING — the actual bug (#109): no throw, byte-identical output.
// Expected strings are built by a loop (never a second JSON.stringify call —
// that would just re-hit the RangeError this file exists to fix).
// ---------------------------------------------------------------------------

describe("deep nesting: no throw, byte-identical to a structurally-built expectation", () => {
  test("10,000 nested arrays", () => {
    let value: unknown = 0;
    for (let i = 0; i < 10_000; i++) value = [value];
    const expected = "[".repeat(10_000) + "0" + "]".repeat(10_000);
    expect(canonicalStringify(value, oracleNFC)).toBe(expected);
  });

  test("10,000 nested objects (single key 'a')", () => {
    let value: unknown = 0;
    for (let i = 0; i < 10_000; i++) value = { a: value };
    const expected = '{"a":'.repeat(10_000) + "0" + "}".repeat(10_000);
    expect(canonicalStringify(value, oracleNFC)).toBe(expected);
  });

  test("10,000 alternating array/object levels", () => {
    let value: unknown = 0;
    let expectedOpen = "";
    let expectedClose = "";
    for (let i = 0; i < 10_000; i++) {
      if (i % 2 === 0) {
        value = [value];
        expectedOpen = "[" + expectedOpen;
        expectedClose += "]";
      } else {
        value = { a: value };
        expectedOpen = '{"a":' + expectedOpen;
        expectedClose += "}";
      }
    }
    expect(canonicalStringify(value, oracleNFC)).toBe(expectedOpen + "0" + expectedClose);
  });

  test("a real tools/list-shaped schema nested 5,000 array levels round-trips through hashToolDefinition", () => {
    // The actual reported shape (#109): a nested array sitting inside a
    // schema property, not the whole schema. Confirms the fix through the
    // real production entry point, at a depth well past the measured
    // pre-fix threshold (2,589) and short of the relay's own
    // forward-serialize ceiling.
    let deep: unknown = 0;
    for (let i = 0; i < 5_000; i++) deep = [deep];
    const schema = { type: "object", properties: { deep } };
    expect(() => hashToolDefinition({ schema })).not.toThrow();
    // Stable across repeated calls (same process) — a prerequisite for
    // "a second launch reads as no drift" (verified end-to-end separately).
    expect(hashToolDefinition({ schema })).toBe(hashToolDefinition({ schema }));
  });
});

// ---------------------------------------------------------------------------
// Individual traps, isolated (each pins ONE behavior a mutation could break).
// ---------------------------------------------------------------------------

describe("individual traps", () => {
  test("enumeration order: integer-like keys sort ascending-numeric FIRST regardless of fold/comparator order", () => {
    // "10" and "2" fold to themselves (identity); a naive emit of the
    // COMPARATOR's string-sorted order would put "10" before "2"
    // (lexicographic). Real JSON.stringify (and Object.keys) puts array-index
    // -like keys in ascending NUMERIC order ahead of everything else.
    const value = { "10": "ten", "2": "two", b: "letter-b", "0": "zero", a: "letter-a" };
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
    expect(canonicalStringify(value, oracleNFC)).toBe('{"0":"zero","2":"two","10":"ten","a":"letter-a","b":"letter-b"}');
  });

  test("non-finite numbers (NaN, Infinity, -Infinity) serialize to null, not omitted", () => {
    const value = { a: NaN, b: Infinity, c: -Infinity, d: 1 };
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
    expect(canonicalStringify(value, oracleNFC)).toBe('{"a":null,"b":null,"c":null,"d":1}');
  });

  test("-0 serializes as the text 0, both bare and inside an array", () => {
    expect(canonicalStringify({ z: -0 }, oracleNFC)).toBe('{"z":0}');
    expect(canonicalStringify([-0], oracleNFC)).toBe("[0]");
  });

  test("lone surrogates are escaped well-formed (\\udXXX), not emitted raw", () => {
    const value = { s: "a\ud800b" };
    const out = canonicalStringify(value, oracleNFC);
    expect(out).toBe(JSON.stringify(value, oracleNFC));
    expect(out).toContain("\\ud800");
    expect(out).not.toContain("\ud800"); // raw lone surrogate must not appear
  });

  test("undefined/function/symbol object members are OMITTED entirely", () => {
    const value = { a: 1, b: undefined, c: () => 1, d: Symbol("x"), e: 2 };
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
    expect(canonicalStringify(value, oracleNFC)).toBe('{"a":1,"e":2}');
  });

  test("undefined/function/symbol ARRAY elements become null, not omitted", () => {
    const value = [1, undefined, () => 1, Symbol("x"), 2];
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
    expect(canonicalStringify(value, oracleNFC)).toBe("[1,null,null,null,2]");
  });

  test("array holes serialize as null (same as an explicit undefined element)", () => {
    const value: unknown[] = [1];
    value[3] = 4; // holes at 1, 2
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
    expect(canonicalStringify(value, oracleNFC)).toBe("[1,null,null,4]");
  });

  test("nesting is capped at MAX_DEPTH: exactly MAX_DEPTH levels serialize, one more throws RangeError", () => {
    let value: unknown = 0;
    for (let i = 0; i < MAX_DEPTH; i++) value = [value];
    expect(canonicalStringify(value, oracleNFC)).toBe("[".repeat(MAX_DEPTH) + "0" + "]".repeat(MAX_DEPTH));
    expect(() => canonicalStringify([value], oracleNFC)).toThrow(RangeError);
  });

  test("a self-referential OBJECT or ARRAY throws (via the depth cap) instead of looping forever", () => {
    const o: Record<string, unknown> = {};
    o.self = o;
    const a: unknown[] = [];
    a.push(a);
    expect(() => canonicalStringify(o, oracleNFC)).toThrow(RangeError);
    expect(() => canonicalStringify(a, oracleNFC)).toThrow(RangeError);
  });

  test("a DAG (same object referenced twice, non-cyclic) does NOT throw", () => {
    const shared = { v: 1 };
    const value = { x: shared, y: shared };
    expect(canonicalStringify(value, oracleNFC)).toBe(JSON.stringify(value, oracleNFC));
  });

  test("a bigint leaf throws TypeError, matching native", () => {
    const value = { n: 10n as unknown };
    expect(() => JSON.stringify(value, oracleNFC)).toThrow(TypeError);
    expect(() => canonicalStringify(value, oracleNFC)).toThrow(TypeError);
  });

  test("empty object and empty array", () => {
    expect(canonicalStringify({}, oracleNFC)).toBe("{}");
    expect(canonicalStringify([], oracleNFC)).toBe("[]");
  });
});
