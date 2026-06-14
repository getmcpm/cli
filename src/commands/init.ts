/**
 * `mcpm init` command — scaffold a starter `mcpm.yaml` stack file.
 *
 * Exports:
 * - STARTER_STACK     — the scaffolded mcpm.yaml content
 * - handleInit()      — pure handler with injectable deps for testing
 * - registerInitCommand() — registers the command on a Commander program
 *
 * History: `init` previously installed curated starter PACKS, but those packs
 * referenced registry identifiers (`io.github.modelcontextprotocol/servers-*`)
 * that no longer resolve in the official registry, so every `init <pack>`
 * installed 0 servers. Blessing specific community servers into default packs
 * is also a trust decision a security tool should not bake in. `init` now
 * scaffolds an empty stack file and points users at `mcpm search`.
 */

import { Command } from "commander";
import chalk from "chalk";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Scaffolded stack file
// ---------------------------------------------------------------------------

export const STARTER_STACK = `# mcpm stack file — declares the MCP servers for this project.
#
# 1. Find servers:  mcpm search <query>
# 2. Add them below under \`servers:\` as  <name>: { version: "<semver>" }
# 3. Lock + install: mcpm lock && mcpm up
#
# Example:
#   servers:
#     io.github.acme/my-server:
#       version: "1.2.3"
version: "1"
servers: {}
`;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InitOptions {
  /** Overwrite an existing stack file. */
  force?: boolean;
}

export interface InitDeps {
  fileExists: (path: string) => Promise<boolean>;
  writeFile: (path: string, content: string) => Promise<void>;
  output: (text: string) => void;
  /** Stack file path; defaults to "mcpm.yaml". */
  stackPath?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm init`. Scaffolds a starter stack file in the working
 * directory unless one already exists (use `force` to overwrite).
 *
 * `legacyPackArg` is accepted only to print a one-line note for users who run
 * the old `mcpm init <pack>` form — the packs were removed.
 */
export async function handleInit(
  legacyPackArg: string | undefined,
  options: InitOptions,
  deps: InitDeps
): Promise<void> {
  const { fileExists, writeFile, output } = deps;
  const stackPath = deps.stackPath ?? "mcpm.yaml";

  if (legacyPackArg !== undefined) {
    output(
      chalk.yellow(
        `Note: curated starter packs were removed (their registry IDs no longer resolve). ` +
          `Scaffolding ${stackPath} instead — find servers with \`mcpm search <query>\`.`
      )
    );
    output("");
  }

  if ((await fileExists(stackPath)) && options.force !== true) {
    output(
      chalk.yellow(
        `${stackPath} already exists — leaving it untouched (use --force to overwrite).`
      )
    );
    return;
  }

  await writeFile(stackPath, STARTER_STACK);

  output(chalk.green(`Created ${stackPath}.`));
  output("");
  output("Next steps:");
  output(`  ${chalk.white("mcpm search <query>")}   find MCP servers in the registry`);
  output(`  edit ${stackPath}              add them under \`servers:\``);
  output(`  ${chalk.white("mcpm lock")}             resolve and lock versions`);
  output(`  ${chalk.white("mcpm up")}               install from the stack file`);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerInitCommand(program: Command): void {
  program
    .command("init [pack]")
    .description("Scaffold a starter mcpm.yaml stack file in the current directory")
    .option("-f, --force", "Overwrite an existing mcpm.yaml")
    .action(async (pack: string | undefined, opts: { force?: boolean }) => {
      const { writeFile, access } = await import("node:fs/promises");

      const deps: InitDeps = {
        fileExists: async (path) => {
          try {
            await access(path);
            return true;
          } catch {
            return false;
          }
        },
        writeFile: (path, content) =>
          writeFile(path, content, { encoding: "utf-8" }),
        output: stdoutOutput,
      };

      await handleInit(pack, { force: opts.force }, deps).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
