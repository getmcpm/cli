/**
 * `mcpm alias` command handler.
 *
 * Manages short aliases for long MCP server names.
 *
 *   mcpm alias fs io.github.domdomegg/filesystem-mcp
 *   mcpm alias --list
 *   mcpm alias --remove fs
 *
 * Aliases are stored in ~/.mcpm/aliases.json and resolved automatically
 * in install, info, remove, enable, and disable commands.
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AliasMap = Record<string, string>;

export interface AliasDeps {
  getAliases: () => Promise<AliasMap>;
  setAlias: (alias: string, serverName: string) => Promise<void>;
  removeAlias: (alias: string) => Promise<void>;
  output: (text: string) => void;
}

export interface AliasOptions {
  list?: boolean;
  remove?: string;
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/** Alias names must be short, alphanumeric identifiers (letters, digits, hyphens, underscores). */
const ALIAS_NAME_RE = /^[\w-]+$/;
const ALIAS_MAX_LENGTH = 64;

function validateAliasName(alias: string): void {
  if (alias.length === 0) {
    throw new Error("Alias name must not be empty.");
  }
  if (alias.length > ALIAS_MAX_LENGTH) {
    throw new Error(`Alias name must be at most ${ALIAS_MAX_LENGTH} characters.`);
  }
  if (!ALIAS_NAME_RE.test(alias)) {
    throw new Error(
      "Alias names must contain only letters, digits, hyphens, and underscores."
    );
  }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleAlias(
  args: string[],
  options: AliasOptions,
  deps: AliasDeps
): Promise<void> {
  const { getAliases, setAlias, removeAlias, output } = deps;

  // --list: show all aliases
  if (options.list) {
    const aliases = await getAliases();
    const entries = Object.entries(aliases);
    if (entries.length === 0) {
      output("No aliases defined. Create one: mcpm alias <shortname> <server-name>");
      return;
    }

    const table = new Table({
      head: [chalk.cyan("Alias"), chalk.cyan("Server Name")],
      style: { head: [], border: [] },
    });

    for (const [alias, name] of entries) {
      table.push([chalk.yellow(alias), chalk.white(name)]);
    }

    output(table.toString());
    return;
  }

  // --remove: delete an alias
  if (options.remove) {
    validateAliasName(options.remove);
    await removeAlias(options.remove);
    output(`Removed alias '${options.remove}'.`);
    return;
  }

  // Set alias: mcpm alias <shortname> <server-name>
  if (args.length < 2) {
    throw new Error("Usage: mcpm alias <shortname> <server-name>\n       mcpm alias --list\n       mcpm alias --remove <shortname>");
  }

  const [alias, serverName] = args;
  validateAliasName(alias);

  if (serverName.length === 0) {
    throw new Error("Server name must not be empty.");
  }
  if (serverName === "__proto__" || serverName === "constructor" || serverName === "prototype") {
    throw new Error("Server name is not allowed.");
  }

  await setAlias(alias, serverName);
  output(`Alias '${alias}' → '${serverName}'`);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerAliasCommand(program: Command): void {
  program
    .command("alias [args...]")
    .description("Create short aliases for MCP server names")
    .option("-l, --list", "List all defined aliases")
    .option("-r, --remove <alias>", "Remove an alias")
    .action(async (args: string[], options: AliasOptions) => {
      const { getAliases, setAlias, removeAlias } = await import("../store/aliases.js");

      try {
        await handleAlias(args, options, {
          getAliases,
          setAlias,
          removeAlias,
          output: stdoutOutput,
        });
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
