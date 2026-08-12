/**
 * `lockPathFor` — the stack→lock path derivation.
 *
 * Two properties matter here, and the second is why this file exists.
 *
 * 1. The output never equals the input. Violating this made `mcpm lock` write the lock
 *    over the user's own stack file (the bug `paths.ts` was extracted to fix).
 * 2. The map is INJECTIVE. Violating this made two different stack files in one
 *    directory share a lock path, so locking one silently destroyed the other's
 *    baselines. Extension-stripping satisfied (1) while failing (2).
 */

import { describe, it, expect } from "vitest";
import { lockPathFor } from "../../stack/paths.js";

describe("lockPathFor", () => {
  // Each row is (stack path, lock path). The pairs that differ only by extension are
  // the regression: under extension-stripping they all collapsed onto
  // "mcpm-lock.yaml".
  const TABLE: ReadonlyArray<readonly [string, string]> = [
    // The overwhelmingly common case — must stay byte-identical forever, because
    // every existing lock file on disk is named this.
    ["mcpm.yaml", "mcpm-lock.yaml"],
    // The collision set.
    ["mcpm.yml", "mcpm-lock.yml"],
    ["mcpm.YAML", "mcpm-lock.YAML"],
    ["mcpm.Yaml", "mcpm-lock.Yaml"],
    // No yaml extension: append rather than invent one. Defaulting to ".yaml" here
    // would re-introduce a collision, since "stack" and "stack.yaml" would meet.
    ["stack", "stack-lock"],
    ["mcpm.yaml.bak", "mcpm.yaml.bak-lock"],
    ["mcpm.yamlx", "mcpm.yamlx-lock"],
    // Directories are untouched — only the final segment's extension moves.
    ["dir/mcpm.yaml", "dir/mcpm-lock.yaml"],
    ["./a.yml", "./a-lock.yml"],
    // Degenerate but legal filenames.
    [".yaml", "-lock.yaml"],
    ["mcpm.", "mcpm.-lock"],
  ];

  it.each(TABLE)("derives %s -> %s", (stack, expected) => {
    expect(lockPathFor(stack)).toBe(expected);
  });

  it("never returns the input — a lock path equal to the stack path overwrites the stack", () => {
    // Mutation caught: dropping the "-lock" infix, or restoring a strip-only
    // derivation for a path the strip does not match.
    for (const [stack] of TABLE) {
      expect(lockPathFor(stack)).not.toBe(stack);
    }
  });

  it("is injective — sibling stack files never share one lock path", () => {
    // Mutation caught: any derivation that normalises the extension away
    // (`replace(/\.ya?ml$/i, "")` + a fixed "-lock.yaml" suffix) collapses the first
    // four rows onto one output and fails here.
    const inputs = TABLE.map(([stack]) => stack);
    const outputs = inputs.map(lockPathFor);
    expect(new Set(outputs).size).toBe(inputs.length);
  });

  it("keeps .yaml and .yml siblings apart in the same directory", () => {
    // The concrete data-loss pair, stated on its own so a regression names itself.
    expect(lockPathFor("mcpm.yml")).not.toBe(lockPathFor("mcpm.yaml"));
  });
});
