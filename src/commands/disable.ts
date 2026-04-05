/**
 * `mcpm disable <name>` command handler.
 *
 * Disables a named MCP server across all (or a specific) client config files
 * by setting `"disabled": true` on the entry. The server remains in config
 * but will not be loaded by the client.
 */

import { Command } from "commander";
import chalk from "chalk";
import { handleToggleServer } from "./toggle.js";
import type { ToggleDeps, ToggleOptions } from "./toggle.js";
import { stdoutOutput } from "../utils/output.js";

// Re-export types for backwards compatibility with tests and barrel.
export type DisableDeps = ToggleDeps;
export type DisableOptions = ToggleOptions;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleDisable(
  name: string,
  options: DisableOptions,
  deps: DisableDeps
): Promise<void> {
  return handleToggleServer(name, true, options, deps);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerDisableCommand(program: Command): void {
  program
    .command("disable <name>")
    .description("Disable an MCP server without removing it from config")
    .option("-c, --client <id>", "only disable in this specific client")
    .action(async (name: string, options: DisableOptions) => {
      const { detectInstalledClients } = await import("../config/detector.js");
      const { getConfigPath } = await import("../config/paths.js");
      const { getAdapter } = await import("../config/adapters/factory.js");

      try {
        await handleDisable(name, options, {
          detectClients: detectInstalledClients,
          getAdapter,
          getConfigPath,
          output: stdoutOutput,
        });
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
