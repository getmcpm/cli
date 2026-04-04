/**
 * `mcpm enable <name>` command handler.
 *
 * Re-enables a previously disabled MCP server across all (or a specific)
 * client config files by removing the `"disabled": true` flag.
 *
 * All external dependencies are injected for testability.
 */

import { Command } from "commander";
import chalk from "chalk";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter } from "../config/adapters/index.js";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EnableDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

export interface EnableOptions {
  client?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleEnable(
  name: string,
  options: EnableOptions,
  deps: EnableDeps
): Promise<void> {
  const { detectClients, getAdapter, getConfigPath, output } = deps;

  let clients = await detectClients();

  if (options.client !== undefined) {
    const target = options.client as ClientId;
    if (!clients.includes(target)) {
      throw new Error(`Client "${target}" is not installed on this machine.`);
    }
    clients = [target];
  }

  // Find which clients have this server.
  const clientsWithServer: ClientId[] = [];
  for (const clientId of clients) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const servers = await adapter.read(configPath);
    if (Object.prototype.hasOwnProperty.call(servers, name)) {
      clientsWithServer.push(clientId);
    }
  }

  if (clientsWithServer.length === 0) {
    const scope = options.client ? `client "${options.client}"` : "any client config";
    throw new Error(`Server '${name}' not found in ${scope}.`);
  }

  // Check which are actually disabled.
  const alreadyEnabled: ClientId[] = [];
  const toEnable: ClientId[] = [];

  for (const clientId of clientsWithServer) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const servers = await adapter.read(configPath);
    if (servers[name]?.disabled === true) {
      toEnable.push(clientId);
    } else {
      alreadyEnabled.push(clientId);
    }
  }

  if (toEnable.length === 0) {
    output(`Server '${name}' is already enabled in ${alreadyEnabled.join(", ")}.`);
    return;
  }

  for (const clientId of toEnable) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    await adapter.setServerDisabled(configPath, name, false);
  }

  output(`Enabled '${name}' in ${toEnable.join(", ")}.`);
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
