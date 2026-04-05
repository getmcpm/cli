/**
 * `mcpm enable <name>` command handler.
 *
 * Re-enables a previously disabled MCP server across all (or a specific)
 * client config files by removing the `"disabled": true` flag.
 */

import { Command } from "commander";
import chalk from "chalk";
import { handleToggleServer } from "./toggle.js";
import type { ToggleDeps, ToggleOptions } from "./toggle.js";
import { stdoutOutput } from "../utils/output.js";

// Re-export types for backwards compatibility with tests and barrel.
export type EnableDeps = ToggleDeps;
export type EnableOptions = ToggleOptions;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleEnable(
  name: string,
  options: EnableOptions,
  deps: EnableDeps
): Promise<void> {
  return handleToggleServer(name, false, options, deps);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerEnableCommand(program: Command): void {
  program
    .command("enable <name>")
    .description("Re-enable a previously disabled MCP server")
    .option("-c, --client <id>", "only enable in this specific client")
    .action(async (name: string, options: EnableOptions) => {
      const { detectInstalledClients } = await import("../config/detector.js");
      const { getConfigPath } = await import("../config/paths.js");
      const { getAdapter } = await import("../config/adapters/factory.js");

      try {
        await handleEnable(name, options, {
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
