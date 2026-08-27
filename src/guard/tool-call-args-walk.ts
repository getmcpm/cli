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
// covered. `tools/call` arguments are small, so no leaf-walk node budget
// (unlike stringLeaves' MAX_LEAF_WALK_NODES) is needed.
const MAX_DEPTH = 1;

/**
 * Yield every {key, value} STRING leaf (bounded to top-level + one nested
 * OBJECT level). Arrays are walked TRANSPARENTLY — recursing into an array
 * element does not increment `depth` — so a batch-style argument shape like
 * `{ items: [{issue_number: "..."}] }` is still covered; only descending into
 * a nested OBJECT consumes the depth budget. (review: TODOS #50 — an earlier
 * version incremented depth on array entry too, which combined with the depth
 * cap to make every array element's own keys unreachable.)
 *
 * `Object.hasOwn` guards inherited keys. Does no key filtering — callers apply
 * their own identifier-shape classifier before matching the value.
 */
export function* stringArgLeaves(node: unknown, depth = 0): Iterable<{ key: string; value: string }> {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) yield* stringArgLeaves(item, depth);
    return;
  }
  if (depth > MAX_DEPTH) return;
  for (const key of Object.keys(node)) {
    if (!Object.hasOwn(node, key)) continue;
    const value = (node as Record<string, unknown>)[key];
    if (typeof value === "string") {
      yield { key, value };
    } else if (value !== null && typeof value === "object") {
      yield* stringArgLeaves(value, depth + 1);
    }
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
