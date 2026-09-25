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
// No leaf-walk NODE budget (unlike stringLeaves' MAX_LEAF_WALK_NODES) is
// needed: the walk below is iterative (an explicit heap-allocated stack, no
// recursion), so its cost is O(nodes visited) with no stack-depth risk
// regardless of how deep a value is nested — the old "arguments are small"
// premise this comment used to state is exactly what failed (#104: a
// `tools/call` argument wrapped in ~2,500+ nested arrays overflowed the prior
// recursive generator well before the relay's own limits engaged). The
// backstop is the relay's 10 MiB per-frame cap, not a node count here.
const MAX_DEPTH = 1;

/**
 * One pending unit of work for the iterative walk below: either a leaf ready
 * to yield (a string-valued object property, tagged with its key), or a
 * container (object or array) still needing its own contents pushed.
 */
type WalkItem =
  | { readonly kind: "leaf"; readonly key: string; readonly value: string }
  | { readonly kind: "container"; readonly node: unknown; readonly depth: number };

/**
 * Yield every {key, value} STRING leaf (bounded to top-level + one nested
 * OBJECT level). Arrays are walked TRANSPARENTLY — descending into an array
 * element does not increment `depth` — so a batch-style argument shape like
 * `{ items: [{issue_number: "..."}] }` is still covered; only descending from
 * an object into one of ITS property values (whether that value is itself an
 * object or an array) consumes one unit of the depth budget. (review: TODOS
 * #50 — an earlier version incremented depth on array entry too, which
 * combined with the depth cap to make every array element's own keys
 * unreachable.)
 *
 * Iterative (explicit stack), not recursive: a plain array `[[[["x"]]]]`
 * nested arbitrarily deep is walked transparently with NO object-depth check
 * gating it (see above), so a recursive `yield*` walk had no bound on stack
 * depth at all — a `tools/call` argument wrapped in enough nested arrays
 * overflowed the call stack (#104) well before hitting any object-depth or
 * node-count budget. The stack here is heap-allocated, so depth costs memory,
 * not call frames.
 *
 * Children are pushed in reverse so they pop in source order — leaf output
 * for every input is IDENTICAL to the prior recursive walk (pinned by a
 * golden-order regression test), including yielding nothing for a raw string
 * sitting directly in an array (only OBJECT-property string values are
 * leaves; `{items: ["a"]}`'s `"a"` has no key and is never yielded).
 *
 * `Object.hasOwn` guards inherited keys. Does no key filtering — callers apply
 * their own identifier-shape classifier before matching the value.
 */
export function* stringArgLeaves(node: unknown, depth = 0): Iterable<{ key: string; value: string }> {
  const stack: WalkItem[] = [{ kind: "container", node, depth }];
  while (stack.length > 0) {
    const item = stack.pop() as WalkItem;
    if (item.kind === "leaf") {
      yield { key: item.key, value: item.value };
      continue;
    }
    const { node: current, depth: curDepth } = item;
    if (current === null || typeof current !== "object") continue;
    if (Array.isArray(current)) {
      // Transparent: same depth, no budget consumed, however deep the array
      // nesting goes.
      for (let i = current.length - 1; i >= 0; i--) {
        stack.push({ kind: "container", node: current[i], depth: curDepth });
      }
      continue;
    }
    if (curDepth > MAX_DEPTH) continue;
    const keys = Object.keys(current);
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i];
      if (!Object.hasOwn(current, key)) continue;
      const value = (current as Record<string, unknown>)[key];
      if (typeof value === "string") {
        stack.push({ kind: "leaf", key, value });
      } else if (value !== null && typeof value === "object") {
        stack.push({ kind: "container", node: value, depth: curDepth + 1 });
      }
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
