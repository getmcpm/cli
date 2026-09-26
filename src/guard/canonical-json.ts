/**
 * #109: an iterative, byte-identical stand-in for `JSON.stringify(value,
 * replacer)` (compact form only — no space argument, the only form pins.ts's
 * `hashLeaf` ever calls).
 *
 * `hashLeaf`'s replacer is a function, and V8 recurses one native stack frame
 * per container level whenever a replacer function is present (the "general
 * path" — the plain-object/array fast path it otherwise takes is skipped).
 * A `tools/list` inputSchema (or an `initialize` capabilities object) nested
 * past ~2,600 array levels / ~2,750 object levels then threw RangeError
 * *inside* the relay's synchronous drift check, which the relay's own
 * try/catch (relay.ts `inspectFailedDecision`) turns into a fail-closed
 * `inspect-rejected` BLOCK of that frame — a schema-side block is a hard
 * block of the server's entire `tools/list`, and blocking `initialize` ends
 * the session. Measured thresholds (Node 24.20.0, this repro): array nesting
 * blocks at depth 2589 (last good 2588), object nesting at 2706 (last good
 * 2705) — both close to the ~2,600 / ~2,750 estimate this fix was filed
 * against. The relay's own forward re-serialize (`serializeMessage`, plain
 * `JSON.stringify` with no replacer) tolerates far deeper nesting before its
 * own RangeError (`forward-serialize-failed`) — this file does not change
 * that ceiling, only removes the earlier, avoidable one in the drift hash.
 *
 * Byte-identity is the whole job: every existing `pins.json` entry is a hash
 * of the CURRENT bytes this function must keep producing, and a schema-side
 * hash mismatch is a hard BLOCK — so any divergence here is a false drift
 * finding on every affected server. `src/guard/__tests__/canonical-json.test.ts`
 * differentially fuzzes this against real `JSON.stringify` (fast-check, all
 * three of pins.ts's replacer forms) and pins hand-picked trap cases.
 *
 * The trick that keeps this small: once a replacer call resolves a property
 * to a NON-container value (string/number/boolean/null, or an
 * undefined/function/symbol that must be OMITTED), that value can never
 * itself recurse — so it is simply hashed off to the real, native
 * `JSON.stringify` for exact leaf encoding (string quoting incl. well-formed
 * lone-surrogate escaping, number formatting, `-0`→"0", non-finite→"null",
 * BigInt→throw, undefined/function/symbol→`undefined`). Only CONTAINERS
 * (arrays / plain objects) need the iterative walk, one stack frame per open
 * container with a cursor into it (never all children pushed up front) —
 * the same shape `stringArgLeaves` (tool-call-args-walk.ts, #104) uses to
 * keep memory bounded by depth, not width.
 *
 * NOT implemented, deliberately: `toJSON`. `JSON.stringify` calls
 * `value.toJSON(key)` before invoking the replacer, for any object that has
 * one (e.g. `Date`). Every value `hashLeaf` ever hashes originates from
 * `JSON.parse` (wire schemas/descriptions/capabilities) or from a plain
 * object literal of hash-string / string / null leaves built by pins.ts
 * itself — neither path can ever produce a `Date` or any other object with
 * an own or inherited `toJSON`. If one ever did reach here, this module
 * would serialize it via `Object.keys` (almost always `{}`) instead of
 * calling `toJSON` — a silent divergence from native, scoped to a case that
 * cannot occur today. Differential-fuzzed inputs are drawn from
 * `fast-check`'s JSON-value arbitraries for the same reason: they cannot
 * generate a `toJSON`-bearing value either, so this gap is not something the
 * fuzz suite could paper over.
 *
 * Cycles: none of `hashLeaf`'s real inputs can contain one (`JSON.parse`
 * output is always a tree; pins.ts's own literals never introduce a back
 * reference). Guarded anyway, defensively, via a `Set` of the PRE-replacer
 * ("raw") container references on the current path — not the post-replacer
 * value, because pins.ts's object-folding replacer allocates a fresh
 * `Object.create(null)` wrapper on every call, so a genuinely cyclic object
 * would never revisit the same POST-replacer identity and an iterative walk
 * (no call-stack depth to eventually RangeError on, unlike the recursive
 * code this replaces) would grow unbounded instead of failing. Tracking the
 * raw identity catches it and throws `TypeError`, matching native's own
 * `TypeError` for a cyclic ARRAY (whose replacer output IS the same raw
 * reference) — a cyclic OBJECT's native error is not something this needs to
 * match exactly, since that shape can't reach `hashLeaf` for real.
 */

/** Same signature `hashLeaf`'s `replacerFor` already returns. */
export type JsonReplacer = (this: unknown, key: string, value: unknown) => unknown;

/** An open container awaiting more of its own members. */
interface Frame {
  /** The value returned FOR this container by the replacer (what its own members are read off of). */
  readonly container: Record<string, unknown> | unknown[];
  /** The PRE-replacer value that produced `container` — tracked only for cycle detection. */
  readonly rawSource: object;
  readonly isArray: boolean;
  /** `Object.keys(container)` for an object (ordinary property order — see module doc); `null` for an array. */
  readonly keys: readonly string[] | null;
  readonly length: number;
  idx: number;
  /** Already-serialized `"key":value` (object) or bare `value` (array) members, in order. */
  readonly parts: string[];
  /** The key/index `container` itself was read under, in ITS parent — used once this frame completes. */
  readonly invokedKey: string;
}

const PUSHED = Symbol("canonical-json:pushed");

/**
 * Iterative equivalent of `JSON.stringify(value, replacer)`. Throws
 * `TypeError` on a BigInt leaf or a cycle (see module doc), matching or
 * (for object cycles) deliberately strengthening native behavior with this
 * specific class of replacer.
 */
export function canonicalStringify(value: unknown, replacer: JsonReplacer): string {
  // Mirrors JSON.stringify's own root handling: SerializeJSONProperty("", { "": value }).
  const wrapper: Record<string, unknown> = { "": value };
  const rawAncestors = new Set<object>();
  const stack: Frame[] = [];

  function pushContainer(container: Record<string, unknown> | unknown[], rawSource: object, invokedKey: string): void {
    rawAncestors.add(rawSource);
    const isArray = Array.isArray(container);
    const keys = isArray ? null : Object.keys(container as Record<string, unknown>);
    const length = isArray ? (container as unknown[]).length : (keys as string[]).length;
    stack.push({ container, rawSource, isArray, keys, length, idx: 0, parts: [], invokedKey });
  }

  // Resolves holder[key] through the replacer. Returns PUSHED (a new frame
  // was opened for a container result), or the already-final JSON text for a
  // leaf (`undefined` meaning "omit this member" — exactly what native
  // `JSON.stringify` returns for undefined/function/symbol).
  function resolveProperty(holder: Record<string, unknown> | unknown[], key: string): string | undefined | typeof PUSHED {
    const raw = (holder as Record<string, unknown>)[key];
    if (raw !== null && typeof raw === "object") {
      if (rawAncestors.has(raw)) throw new TypeError("Converting circular structure to JSON");
    }
    const resolved = replacer.call(holder, key, raw);
    if (resolved !== null && typeof resolved === "object") {
      pushContainer(resolved as Record<string, unknown> | unknown[], raw as object, key);
      return PUSHED;
    }
    // A non-container result can't recurse — hand it to the real
    // JSON.stringify for exact leaf encoding (see module doc). Also where a
    // BigInt throws and undefined/function/symbol correctly become `undefined`.
    return JSON.stringify(resolved);
  }

  const root = resolveProperty(wrapper, "");
  if (root !== PUSHED) {
    if (root === undefined) {
      // Unreachable from every current hashLeaf call site (all pass an
      // object, string, or a `?? null`-guarded value) — kept as a loud
      // failure rather than silently hashing "undefined".
      throw new TypeError("canonicalStringify: value has no JSON representation");
    }
    return root;
  }

  for (;;) {
    const top = stack[stack.length - 1];
    if (top.idx >= top.length) {
      const str = top.isArray ? `[${top.parts.join(",")}]` : `{${top.parts.join(",")}}`;
      rawAncestors.delete(top.rawSource);
      stack.pop();
      const parent = stack[stack.length - 1];
      if (parent === undefined) return str;
      if (parent.isArray) parent.parts.push(str);
      else parent.parts.push(`${JSON.stringify(top.invokedKey)}:${str}`);
      continue;
    }
    const key = top.isArray ? String(top.idx) : (top.keys as readonly string[])[top.idx];
    top.idx++;
    const r = resolveProperty(top.container, key);
    if (r === PUSHED) continue;
    if (top.isArray) top.parts.push(r === undefined ? "null" : r);
    else if (r !== undefined) top.parts.push(`${JSON.stringify(key)}:${r}`);
  }
}
