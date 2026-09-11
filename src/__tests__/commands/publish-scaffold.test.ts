/**
 * `mcpm publish scaffold` — the wizard's description prompt.
 *
 * The cap rule itself lives in (and is pinned by) publish-manifest.test.ts.
 * This pins the one thing that file cannot see: that the wizard actually uses
 * it. Re-inlining a `value.length <= 100` check here is the original #85 bug —
 * `.length` counts UTF-16 units, so it refuses a 51-emoji description the
 * manifest schema and the registry both accept.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Command } from "commander";
import { validateDescription } from "../../commands/publish/manifest.js";

const input = vi.fn().mockResolvedValue("x");
const select = vi.fn().mockResolvedValue("npm");
const writeFile = vi.fn().mockResolvedValue(undefined);

vi.mock("@inquirer/prompts", () => ({ input: (...a: unknown[]) => input(...a), select: (...a: unknown[]) => select(...a) }));
vi.mock("node:fs/promises", () => ({ writeFile: (...a: unknown[]) => writeFile(...a) }));
vi.mock("../../utils/output.js", () => ({ stdoutOutput: () => {} }));

describe("publish scaffold", () => {
  beforeEach(() => {
    input.mockClear();
    select.mockClear();
    writeFile.mockClear();
  });

  it("gates the description prompt with the shared cap rule, not a private copy", async () => {
    const { registerPublishCommand } = await import("../../commands/publish/index.js");
    const program = new Command();
    program.exitOverride();
    registerPublishCommand(program);

    await program.parseAsync(["publish", "scaffold"], { from: "user" });

    const prompt = input.mock.calls
      .map(([opts]) => opts as { message: string; validate?: unknown })
      .find((o) => o.message === "Short description:");

    expect(prompt).toBeDefined();
    expect(prompt?.validate).toBe(validateDescription);
  });
});
