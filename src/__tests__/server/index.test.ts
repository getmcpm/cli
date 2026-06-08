/**
 * Tests for src/server/index.ts — tool registration completeness (fix F.1).
 *
 * Guards against tool/registration divergence: the mcpm_up tool shipped in
 * TOOL_DEFINITIONS but was never registered (the bug PR #64 fixes). This test
 * asserts that registerTools() wires up every TOOL_DEFINITIONS name exactly once,
 * so any future tool added to the definitions but forgotten in registration fails
 * CI instead of silently never being exposed by `mcpm serve`.
 */

import { describe, it, expect, vi } from "vitest";
import { registerTools } from "../../server/index.js";
import { TOOL_DEFINITIONS } from "../../server/tools.js";
import type { ServerDeps } from "../../server/handlers.js";

describe("registerTools (fix F.1)", () => {
  it("registers every tool in TOOL_DEFINITIONS exactly once", () => {
    const registerTool = vi.fn();
    // Handlers are not invoked during registration, so a stub deps object is safe.
    const deps = {} as ServerDeps;

    registerTools({ registerTool } as never, deps);

    const registeredNames = registerTool.mock.calls.map((c) => c[0] as string);
    const expectedNames = TOOL_DEFINITIONS.map((t) => t.name);

    // Every defined tool is registered...
    for (const name of expectedNames) {
      expect(registeredNames).toContain(name);
    }
    // ...exactly once, and nothing extra is registered.
    expect(registeredNames.sort()).toEqual([...expectedNames].sort());
    expect(registeredNames).toHaveLength(expectedNames.length);
  });

  it("registers mcpm_up specifically (the PR #64 regression guard)", () => {
    const registerTool = vi.fn();
    registerTools({ registerTool } as never, {} as ServerDeps);
    const registeredNames = registerTool.mock.calls.map((c) => c[0] as string);
    expect(registeredNames).toContain("mcpm_up");
  });
});
