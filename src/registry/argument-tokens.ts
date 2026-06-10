/**
 * argumentTokens — the single, shared extractor of security-relevant string
 * tokens from a runtime Argument.
 *
 * Two extractors, by token surface:
 *   - argumentTokens (name + value + valueHint) — the full user-facing text
 *     surface, for the prompt-injection scan (scanner/tier1.ts), which must
 *     read documentation hints too.
 *   - argvTokens (name + value only) — the tokens that actually reach the
 *     launch argv, for the rendered command (install.ts normalizeRuntimeArgs)
 *     and the F4 dangerous-flag match (scanner/patterns.ts). They share this
 *     module so the flagged surface and the executed surface cannot diverge.
 *
 * Contract: both are TOTAL over string | named | positional | unknown-future,
 * and always return a (possibly empty) NEW array of defined strings; never
 * mutate input.
 *
 *                                      argumentTokens        argvTokens
 *   "--verbose"                        ["--verbose"]         ["--verbose"]
 *   {name:"--rm"}                      ["--rm"]              ["--rm"]
 *   {value:"-y"}                       ["-y"]                ["-y"]
 *   {name:"--port", value:"8089"}      ["--port","8089"]     ["--port","8089"]
 *   {valueHint:"directory"}            ["directory"]         []
 *   {} / unknown shape                 []                    []
 *
 * `type` is excluded from both (a structural enum, not free text); description/
 * format survive via .passthrough() but are NOT returned (advisory, never a
 * launch token, and including them would over-flag).
 */

import type { Package } from "./types.js";

/** The element type of runtimeArguments after the ArgumentSchema widening. */
export type RuntimeArgument = NonNullable<Package["runtimeArguments"]>[number];

export function argumentTokens(arg: RuntimeArgument): string[] {
  if (typeof arg === "string") return [arg];
  const out: string[] = [];
  if (typeof arg.name === "string") out.push(arg.name);
  if (typeof arg.value === "string") out.push(arg.value);
  if (typeof arg.valueHint === "string") out.push(arg.valueHint);
  return out;
}

/**
 * argvTokens — the subset of argumentTokens actually rendered into the launch
 * argv: `name` and `value` only. EXCLUDES `valueHint` (a documentation
 * placeholder like "directory", never a literal CLI token). Use this for
 * checks scoped to what actually runs — the rendered command and the F4
 * dangerous-flag match — so a server that merely *documents* a positional slot
 * as valueHint:"--import" is neither flagged nor executed on it.
 */
export function argvTokens(arg: RuntimeArgument): string[] {
  if (typeof arg === "string") return [arg];
  const out: string[] = [];
  if (typeof arg.name === "string") out.push(arg.name);
  if (typeof arg.value === "string") out.push(arg.value);
  return out;
}
