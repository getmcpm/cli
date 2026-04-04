/**
 * Tests for src/commands/completions.ts
 */

import { describe, it, expect, vi } from "vitest";
import { handleCompletions } from "../../commands/completions.js";
import type { ShellType } from "../../commands/completions.js";

describe("handleCompletions", () => {
  it("generates bash completions containing mcpm commands", () => {
    const output = vi.fn();
    handleCompletions("bash", { output });
    expect(output).toHaveBeenCalledOnce();
    const script = output.mock.calls[0][0] as string;
    expect(script).toContain("_mcpm_completions");
    expect(script).toContain("search");
    expect(script).toContain("install");
    expect(script).toContain("disable");
    expect(script).toContain("enable");
    expect(script).toContain("complete -F");
  });

  it("generates zsh completions with command descriptions", () => {
    const output = vi.fn();
    handleCompletions("zsh", { output });
    const script = output.mock.calls[0][0] as string;
    expect(script).toContain("compdef _mcpm mcpm");
    expect(script).toContain("search:Search");
    expect(script).toContain("disable:Disable");
  });

  it("generates fish completions with subcommand completions", () => {
    const output = vi.fn();
    handleCompletions("fish", { output });
    const script = output.mock.calls[0][0] as string;
    expect(script).toContain("complete -c mcpm");
    expect(script).toContain("__fish_use_subcommand");
    expect(script).toContain("search");
    expect(script).toContain("disable");
  });

  it("includes client IDs in completions", () => {
    const shells: ShellType[] = ["bash", "zsh", "fish"];
    for (const shell of shells) {
      const output = vi.fn();
      handleCompletions(shell, { output });
      const script = output.mock.calls[0][0] as string;
      expect(script).toContain("claude-desktop");
      expect(script).toContain("cursor");
      expect(script).toContain("vscode");
      expect(script).toContain("windsurf");
    }
  });
});
