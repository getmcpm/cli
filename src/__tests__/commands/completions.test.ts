/**
 * Tests for src/commands/completions.ts
 */

import { describe, it, expect, vi } from "vitest";
import { handleCompletions } from "../../commands/completions.js";
import type { ShellType } from "../../commands/completions.js";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

describe("handleCompletions", () => {
  it("offers only the two scope profiles while preserving other client commands", () => {
    const output = vi.fn(); handleCompletions("bash", { output });
    const script = output.mock.calls[0][0] as string;
    const home = mkdtempSync(path.join(tmpdir(), "mcpm-completion-test-"));
    const complete = (command: string) => execFileSync("/bin/bash", ["--noprofile", "--norc", "-c", `${script}\nCOMP_WORDS=(mcpm ${command} /tmp --client ''); COMP_CWORD=4; _mcpm_completions; printf '%s\\n' "\${COMPREPLY[@]}"`], { encoding: "utf8", env: { PATH: "/usr/bin:/bin", HOME: home } }).trim().split("\n");
    try {
      expect(complete("scope")).toEqual(["claude-code", "vscode"]);
      expect(complete("install")).toContain("claude-desktop");
    } finally { rmSync(home, { recursive: true, force: true }); }
    for (const shell of ["zsh", "fish"] as const) {
      const generated = vi.fn(); handleCompletions(shell, { output: generated });
      const text = generated.mock.calls[0][0] as string;
      expect(text).toContain("claude-code vscode");
      expect(text).not.toContain("Inventory Claude Code project scopes");
      expect(text).toContain("claude-desktop");
    }
  });
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

  it("includes the newer top-level commands in every shell (no stale command list)", () => {
    // Regression guard: completions historically omitted guard/secrets/lock/up/
    // diff/export/outdated/alias/why/publish. Each must appear in all 3 shells.
    const newer = ["guard", "secrets", "lock", "up", "diff", "export", "outdated", "alias", "why", "publish"];
    const shells: ShellType[] = ["bash", "zsh", "fish"];
    for (const shell of shells) {
      const output = vi.fn();
      handleCompletions(shell, { output });
      const script = output.mock.calls[0][0] as string;
      for (const cmd of newer) {
        expect(script, `${shell} completions should mention "${cmd}"`).toContain(cmd);
      }
    }
  });

  it("completes guard and secrets subcommands", () => {
    const shells: ShellType[] = ["bash", "zsh", "fish"];
    for (const shell of shells) {
      const output = vi.fn();
      handleCompletions(shell, { output });
      const script = output.mock.calls[0][0] as string;
      // a representative subcommand from each group
      expect(script).toContain("list-signatures");
      expect(script).toContain("migrate");
    }
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
