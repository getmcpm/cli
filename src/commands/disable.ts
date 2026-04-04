/**
 * `mcpm disable <name>` command handler.
 *
 * Disables a named MCP server across all (or a specific) client config files
 * by setting `"disabled": true` on the entry. The server remains in config
 * but will not be loaded by the client.
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

export interface DisableDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

export interface DisableOptions {
  client?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleDisable(
  name: string,
  options: DisableOptions,
  deps: DisableDeps
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

  // Check if already disabled everywhere.
  const alreadyDisabled: ClientId[] = [];
  const toDisable: ClientId[] = [];

  for (const clientId of clientsWithServer) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const servers = await adapter.read(configPath);
    if (servers[name]?.disabled === true) {
      alreadyDisabled.push(clientId);
    } else {
      toDisable.push(clientId);
    }
  }

  if (toDisable.length === 0) {
    output(`Server '${name}' is already disabled in ${alreadyDisabled.join(", ")}.`);
    return;
  }

  for (const clientId of toDisable) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    await adapter.setServerDisabled(configPath, name, true);
  }

  output(`Disabled '${name}' in ${toDisable.join(", ")}.`);
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
