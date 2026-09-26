/**
 * #109: an iterative, byte-identical stand-in for `JSON.stringify(value,
 * replacer)` (compact form — the only one pins.ts's `hashLeaf` calls).
 *
 * `JSON.stringify` recurses once per nesting level. With `hashLeaf`'s
 * replacer it overflowed the stack at ~2,590 nested arrays / ~2,710 nested
 * objects (absolute frame depth, Node 24.20.0), below the ~5,970 levels the
 * relay's own forward re-serialize tolerates — so a deep `tools/list` schema
 * or `initialize.capabilities` was blocked as `inspect-rejected` by the drift
 * hash rather than by anything about the frame.
 *
 * Byte identity is the whole job: every `pins.json` entry is a hash of these
 * bytes, and a schema-side mismatch is a hard BLOCK. The walk calls the
 * replacer exactly as `JSON.stringify` does (holder as `this`, members in
 * `Object.keys` order of the replacer's RESULT) and hands every non-container
 * result to the native `JSON.stringify` for leaf encoding (string escaping,
 * number formatting, `-0`, non-finite → `null`, BigInt → throw,
 * undefined/function/symbol → omitted, or `null` in an array). Output is
 * appended once to a flat buffer — never re-joined per level — so time and
 * memory are linear in the output, not depth × size.
 *
 * Not implemented: `toJSON`. `hashLeaf` only ever sees values parsed from JSON
 * and pins.ts's own literals of strings, none of which can carry a callable
 * `toJSON`; such a value would be serialized by its keys instead.
 */

/** Same signature `hashLeaf`'s `replacerFor` already returns. */
export type JsonReplacer = (this: unknown, key: string, value: unknown) => unknown;

// ponytail: a flat depth cap instead of a cycle-tracking set — it bounds the
// explicit stack's memory on a 10 MiB frame (one entry per level) and turns a
// cycle (unreachable: JSON.parse output is a tree) into a throw. Far deeper
// than the relay forwards on Node 24 (~5,970) or stringLeaves' 100,000-node
// budget lets through on tools/list; raise it if a runtime ever forwards
// deeper initialize capabilities than this.
export const MAX_DEPTH = 100_000;

interface Frame {
  readonly container: Record<string, unknown> | unknown[];
  /** `null` for an array. */
  readonly keys: readonly string[] | null;
  readonly length: number;
  idx: number;
  /** A member has been written (object members can be omitted, so idx can't tell). */
  wrote: boolean;
}

export function canonicalStringify(value: unknown, replacer: JsonReplacer): string {
  // Flushed every 4,096 tokens so the token array and its many tiny strings
  // stay short-lived; the chunks total about the output's own size.
  const chunks: string[] = [];
  let out: string[] = [];
  const emit = (s: string): void => {
    if (out.push(s) >= 4096) {
      chunks.push(out.join(""));
      out = [];
    }
  };
  const stack: Frame[] = [];

  const open = (container: Record<string, unknown> | unknown[], prefix: string): void => {
    if (stack.length >= MAX_DEPTH) throw new RangeError(`canonicalStringify: nesting deeper than ${MAX_DEPTH}`);
    const keys = Array.isArray(container) ? null : Object.keys(container);
    const length = keys === null ? (container as unknown[]).length : keys.length;
    stack.push({ container, keys, length, idx: 0, wrote: false });
    emit(prefix + (keys === null ? "[" : "{"));
  };

  // JSON.stringify's own root handling: SerializeJSONProperty("", { "": value }).
  const root = replacer.call({ "": value }, "", value);
  if (root === null || typeof root !== "object") {
    const text = JSON.stringify(root);
    // Unreachable from hashLeaf (every call site passes an object, a string, or
    // a `?? null`-guarded value); fail loudly rather than hash "undefined".
    if (text === undefined) throw new TypeError("canonicalStringify: value has no JSON representation");
    return text;
  }
  open(root as Record<string, unknown> | unknown[], "");

  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.idx >= top.length) {
      emit(top.keys === null ? "]" : "}");
      stack.pop();
      continue;
    }
    const key = top.keys === null ? String(top.idx) : top.keys[top.idx];
    top.idx++;
    const resolved = replacer.call(top.container, key, (top.container as Record<string, unknown>)[key]);
    const isContainer = resolved !== null && typeof resolved === "object";
    const text = isContainer ? "" : JSON.stringify(resolved);
    if (text === undefined && top.keys !== null) continue; // omitted object member
    const prefix = (top.wrote ? "," : "") + (top.keys === null ? "" : `${JSON.stringify(key)}:`);
    top.wrote = true;
    if (isContainer) open(resolved as Record<string, unknown> | unknown[], prefix);
    else emit(prefix + (text ?? "null"));
  }
  chunks.push(out.join(""));
  return chunks.join("");
}
