/**
 * Completions ↔ command-surface invariant.
 *
 * The shell completion scripts hardcode command/subcommand lists in THREE places
 * (bash `SUBCOMMANDS`, the zsh `commands=()` block, the fish `-a` lines). Those
 * can silently drift from the real Commander program — that is exactly how the
 * removed `init developer/data/web` starter packs survived in the completions
 * after the feature was deleted. This test ties all three to the live program
 * (built via registerCommands), so adding or removing a command/subcommand fails
 * CI unless the completions are updated in lockstep.
 */

import { describe, it, expect } from "vitest";
import { Command } from "commander";
import { registerCommands } from "../../commands/index.js";
import {
  handleCompletions,
  SUBCOMMANDS,
  GUARD_SUBCOMMANDS,
  SECRETS_SUBCOMMANDS,
  type ShellType,
} from "../../commands/completions.js";

/** The actual top-level command names registered on the program. */
function programCommandNames(): string[] {
  const program = new Command();
  registerCommands(program);
  return program.commands.map((c) => c.name()).sort();
}

/** Subcommand names of a given top-level command on the live program. */
function programSubcommandNames(parent: string): string[] {
  const program = new Command();
  registerCommands(program);
  const cmd = program.commands.find((c) => c.name() === parent);
  if (!cmd) throw new Error(`command "${parent}" not registered`);
  return cmd.commands.map((c) => c.name()).sort();
}

/** Capture a generated completion script string. */
function script(shell: ShellType): string {
  const lines: string[] = [];
  handleCompletions(shell, { output: (t) => lines.push(t) });
  return lines.join("\n");
}

/** Command names the zsh script offers under its top-level `commands=()` block. */
function zshCommandNames(): string[] {
  return [...script("zsh").matchAll(/^\s*'([a-z][a-z0-9-]*):/gm)].map((m) => m[1]!).sort();
}

/** Command names the fish script offers via `__fish_use_subcommand -a <cmd>`. */
function fishCommandNames(): string[] {
  return [...script("fish").matchAll(/__fish_use_subcommand'\s+-a\s+(\S+)/g)].map((m) => m[1]!).sort();
}

describe("completions ↔ command-surface invariant", () => {
  it("bash SUBCOMMANDS exactly matches the registered top-level commands", () => {
    expect([...SUBCOMMANDS].sort()).toEqual(programCommandNames());
  });

  it("the zsh command list exactly matches the registered top-level commands", () => {
    expect(zshCommandNames()).toEqual(programCommandNames());
  });

  it("the fish command list exactly matches the registered top-level commands", () => {
    expect(fishCommandNames()).toEqual(programCommandNames());
  });

  it("GUARD_SUBCOMMANDS exactly matches the registered `guard` subcommands", () => {
    expect(GUARD_SUBCOMMANDS.split(" ").sort()).toEqual(programSubcommandNames("guard"));
  });

  it("SECRETS_SUBCOMMANDS exactly matches the registered `secrets` subcommands", () => {
    expect(SECRETS_SUBCOMMANDS.split(" ").sort()).toEqual(programSubcommandNames("secrets"));
  });

  it("the `completions` shell argument list matches the valid shells", () => {
    // bash/zsh/fish are the only shells handleCompletions renders.
    for (const shell of ["bash", "zsh", "fish"] as const) {
      expect(script(shell)).toContain("bash zsh fish");
    }
  });

  // Regression for the dogfood-found stale-pack bug: `init` no longer takes a
  // curated-pack argument, so no completion script may enumerate init arguments.
  it("no script enumerates `init` arguments (curated packs were removed)", () => {
    expect(script("bash")).not.toMatch(/^\s*init\)/m);
    expect(script("zsh")).not.toMatch(/^\s*init\)/m);
    expect(script("fish")).not.toContain("__fish_seen_subcommand_from init");
    for (const shell of ["bash", "zsh", "fish"] as const) {
      expect(script(shell)).not.toContain("developer data web");
    }
  });
});
