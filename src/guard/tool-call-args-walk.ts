/**
 * Shared `tools/call` argument-tree walker for bespoke key+value detectors
 * (detectShellMetacharArgs #50, detectQueryControlArgs #51, ...). Each
 * detector applies its own key classifier and value matcher; this module only
 * extracts the frame and walks the tree.
 *
 * Extracted out of shell-metachar-args.ts (#50) when #51 needed the identical
 * walk — both detectors only differ in which keys/values they flag, not in
 * how they reach a tool_call_args string leaf.
 */

// Top-level + one nested object level of OBJECT nesting — matches exfilKeys'
// depth cap. Arrays are walked transparently and do not themselves consume
// this budget, so a batch-style `{ items: [{...}] }` argument is still
// covered.
//
// No leaf-walk NODE budget (unlike stringLeaves' MAX_LEAF_WALK_NODES): the
// walk below is iterative and its stack grows with nesting DEPTH only, never
// with width, so it costs O(nodes visited) time and O(depth) memory however
// the argument is shaped. The old "arguments are small" premise is what
// failed in #104: a `tools/call` argument wrapped in ~2,600 nested arrays
// overflowed the prior recursive generator (Node 24.20.0).
const MAX_DEPTH = 1;

/** A container being walked, plus a cursor into it. */
interface Frame {
  readonly node: object;
  /** Own keys of an object, snapshotted on entry; `null` for an array. */
  readonly keys: readonly string[] | null;
  readonly depth: number;
  next: number;
}

/**
 * Yield every {key, value} STRING leaf (bounded to top-level + one nested
 * OBJECT level). Arrays are walked TRANSPARENTLY — descending into an array
 * element does not increment `depth` — so a batch-style argument shape like
 * `{ items: [{issue_number: "..."}] }` is still covered; only descending from
 * an object into one of ITS property values consumes the depth budget.
 * (review: TODOS #50 — an earlier version incremented depth on array entry
 * too, which combined with the depth cap to make every array element's own
 * keys unreachable.) A raw string directly inside an array has no key and is
 * never yielded.
 *
 * Iterative, not recursive (#104): array nesting is not bounded by the depth
 * cap, so the old `yield*` recursion had no bound on call-stack depth. Each
 * frame keeps a cursor rather than pushing every child up front — the first
 * iterative version did that, and a ~10 MiB flat-array argument then cost
 * ~300–500 MB of extra peak RSS. Visit order, the lazy per-key value read and
 * the output are the recursive walk's.
 *
 * `Object.hasOwn` guards inherited keys. Does no key filtering — callers apply
 * their own identifier-shape classifier before matching the value.
 */
export function* stringArgLeaves(node: unknown, depth = 0): Iterable<{ key: string; value: string }> {
  const stack: Frame[] = [];
  const enter = (value: unknown, d: number): void => {
    if (value === null || typeof value !== "object") return;
    if (Array.isArray(value)) stack.push({ node: value, keys: null, depth: d, next: 0 });
    else if (d <= MAX_DEPTH) stack.push({ node: value, keys: Object.keys(value), depth: d, next: 0 });
  };
  enter(node, depth);
  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (top.keys === null) {
      const arr = top.node as readonly unknown[];
      if (top.next >= arr.length) stack.pop();
      else enter(arr[top.next++], top.depth);
      continue;
    }
    if (top.next >= top.keys.length) {
      stack.pop();
      continue;
    }
    const key = top.keys[top.next++];
    if (!Object.hasOwn(top.node, key)) continue;
    const value = (top.node as Record<string, unknown>)[key];
    if (typeof value === "string") yield { key, value };
    else enter(value, top.depth + 1);
  }
}

/**
 * Extract {toolName, args} from a `tools/call` request. Returns null for
 * every other frame shape (response, notification, a call with no/malformed
 * arguments) so detectors can early-return with a single check.
 */
export function toolCallArguments(msg: unknown): { toolName: string; args: Record<string, unknown> } | null {
  if (msg === null || typeof msg !== "object") return null;
  if (!("method" in msg) || (msg as { method?: unknown }).method !== "tools/call") return null;
  if (!("params" in msg)) return null;
  const params = (msg as { params?: { name?: unknown; arguments?: unknown } }).params;
  const args = params?.arguments;
  if (args === null || typeof args !== "object" || Array.isArray(args)) return null;
  const toolName = typeof params?.name === "string" ? params.name : "<unnamed>";
  return { toolName, args: args as Record<string, unknown> };
}
