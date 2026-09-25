/**
 * `stringArgLeaves` (#104) — a `tools/call` argument's KEY+VALUE string-leaf
 * walk, shared by the three structural detectors (shell-metachar-args.ts,
 * query-control-args.ts, cli-flag-injection-args.ts).
 *
 * Until this fix the walk was a RECURSIVE generator (`yield*`) that unwrapped
 * arrays TRANSPARENTLY with no depth check gating the unwrap — so a
 * `tools/call` argument wrapped in enough nested arrays (measured: ~2,500 on
 * this machine under Node 24.20.0, well below the ~6,000 that overflows
 * `JSON.stringify` for the same shape) overflowed the call stack with
 * `RangeError: Maximum call stack size exceeded`. This suite pins two things:
 * the walk no longer recurses (100k/500k-deep inputs complete without
 * throwing), and its OUTPUT is byte-for-byte identical to the old recursive
 * implementation's — order, depth cap, array transparency, `Object.hasOwn`
 * guard, and "a raw string sitting directly in an array has no key and is
 * never yielded" all included.
 *
 * The golden table below was captured by running the PRIOR recursive
 * implementation over each shape (before this fix landed) and recording its
 * exact output; the assertions here are those captured values, not a
 * re-derivation of the semantics.
 */

import { describe, expect, test } from "vitest";
import { stringArgLeaves } from "../tool-call-args-walk.js";

function leaves(node: unknown): Array<{ key: string; value: string }> {
  return [...stringArgLeaves(node)];
}

describe("stringArgLeaves — golden order/semantics (pinned against the prior recursive implementation)", () => {
  test("flat object: every string leaf, in key order", () => {
    expect(leaves({ a: "1", b: "2" })).toEqual([
      { key: "a", value: "1" },
      { key: "b", value: "2" },
    ]);
  });

  test("one nested object level: parent leaf, then child leaves, then next parent leaf", () => {
    expect(leaves({ a: "1", b: { c: "2", d: "3" }, e: "4" })).toEqual([
      { key: "a", value: "1" },
      { key: "c", value: "2" },
      { key: "d", value: "3" },
      { key: "e", value: "4" },
    ]);
  });

  test("two nested object levels: the second level is cut off (MAX_DEPTH=1)", () => {
    expect(leaves({ a: { b: { c: "deep" } } })).toEqual([]);
  });

  test("array of objects: batch-style arguments stay reachable (TODOS #50)", () => {
    expect(leaves({ items: [{ id: "x" }, { id: "y" }] })).toEqual([
      { key: "id", value: "x" },
      { key: "id", value: "y" },
    ]);
  });

  test("array of arrays of objects: arrays nest transparently with no extra depth cost", () => {
    expect(leaves({ items: [[{ id: "x" }], [{ id: "y" }]] })).toEqual([
      { key: "id", value: "x" },
      { key: "id", value: "y" },
    ]);
  });

  test("mixed array/object nesting: object->array->object still costs exactly one depth unit", () => {
    // a (depth 0, direct leaf) — items (array, transparent) -> {id, nested}
    // (depth 1, at the cap: id is reachable, nested's own contents are not).
    expect(leaves({ a: "1", items: [{ id: "x", nested: { y: "2" } }] })).toEqual([
      { key: "a", value: "1" },
      { key: "id", value: "x" },
    ]);
  });

  test("non-string leaves (number, boolean, null) are silently skipped, not yielded", () => {
    expect(leaves({ a: 1, b: true, c: null, d: "keep" })).toEqual([{ key: "d", value: "keep" }]);
  });

  test("inherited keys via Object.create are not walked (Object.hasOwn / Object.keys own-only)", () => {
    const proto = { inherited: "should-not-appear" };
    const child = Object.create(proto) as Record<string, unknown>;
    child.own = "value";
    expect(leaves(child)).toEqual([{ key: "own", value: "value" }]);
  });

  test("empty object and empty array yield nothing", () => {
    expect(leaves({})).toEqual([]);
    expect(leaves({ items: [] })).toEqual([]);
  });

  test("a raw string sitting directly in an array has no key and is never yielded", () => {
    expect(leaves({ items: ["a", "b"] })).toEqual([]);
  });

  test("a top-level array input (no wrapping object) still finds object leaves inside", () => {
    expect(leaves(["a", { id: "x" }])).toEqual([{ key: "id", value: "x" }]);
  });

  test("a top-level non-object input yields nothing", () => {
    expect(leaves("just-a-string")).toEqual([]);
    expect(leaves(42)).toEqual([]);
    expect(leaves(null)).toEqual([]);
  });

  test("three nested object levels: only the first two are reachable, the third is cut off", () => {
    expect(leaves({ a: { b: { c: { d: "unreachable" } } } })).toEqual([]);
  });
});

describe("stringArgLeaves — no longer recurses (#104)", () => {
  function deepArrayJSON(depth: number, leaf: unknown): unknown {
    return JSON.parse("[".repeat(depth) + JSON.stringify(leaf) + "]".repeat(depth));
  }

  test("a tool argument wrapped in 100,000 nested arrays does not throw", () => {
    const args = { items: deepArrayJSON(100_000, "x") };
    expect(() => leaves(args)).not.toThrow();
  });

  test("...and does not yield the buried raw string (no key owns it) — same as a shallow wrap", () => {
    const args = { items: deepArrayJSON(100_000, "x") };
    expect(leaves(args)).toEqual([]);
  });

  test("an object leaf buried behind 100,000 array-nesting levels is still reachable (array transparency holds at scale)", () => {
    const args = { items: deepArrayJSON(100_000, { id: "y" }) };
    expect(leaves(args)).toEqual([{ key: "id", value: "y" }]);
  });

  test("500,000-deep nesting still completes without throwing (heap-bounded, not stack-bounded)", () => {
    const args = { items: deepArrayJSON(500_000, "x") };
    expect(() => leaves(args)).not.toThrow();
  });

  test("terminates promptly on a pathological depth", () => {
    const args = { items: deepArrayJSON(500_000, "x") };
    const start = Date.now();
    leaves(args);
    expect(Date.now() - start).toBeLessThan(5_000);
  });
});
