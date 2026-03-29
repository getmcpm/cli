/**
 * `mcpm remove <name>` command handler.
 *
 * Removes a named MCP server from all (or a specific) installed client config
 * files and from the mcpm store.
 *
 * All external dependencies are injected for testability.
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter } from "../config/adapters/index.js";
import type { detectInstalledClients } from "../config/detector.js";
import type { getConfigPath } from "../config/paths.js";
import type { removeInstalledServer } from "../store/servers.js";

// ---------------------------------------------------------------------------
// Deps interface
// ---------------------------------------------------------------------------

export interface RemoveDeps {
  detectClients: typeof detectInstalledClients;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: typeof getConfigPath;
  removeFromStore: typeof removeInstalledServer;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

export interface RemoveOptions {
  yes?: boolean;
  client?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm remove <name>`.
 * Returns without throwing on successful removal or cancelled prompt.
 * Throws a descriptive Error for invalid inputs.
 */
export async function removeHandler(
  name: string,
  options: RemoveOptions,
  deps: RemoveDeps
): Promise<void> {
  const { detectClients, getAdapter, getConfigPath, removeFromStore, confirm, output } = deps;

  // 1. Detect which clients are installed.
  let installedClients = await detectClients();

  // 2. Apply --client filter if provided.
  if (options.client !== undefined) {
    const targetClient = options.client as ClientId;
    if (!installedClients.includes(targetClient)) {
      throw new Error(
        `Client "${targetClient}" is not installed on this machine.`
      );
    }
    installedClients = [targetClient];
  }

  // 3. For each client, check if the server is present.
  const clientsWithServer: ClientId[] = [];

  for (const clientId of installedClients) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const servers = await adapter.read(configPath);

    if (Object.prototype.hasOwnProperty.call(servers, name)) {
      clientsWithServer.push(clientId);
    }
  }

  // 4. Handle not-found case.
  if (clientsWithServer.length === 0) {
    const scope = options.client ? `client "${options.client}"` : "any client config";
    throw new Error(`Server '${name}' not found in ${scope}.`);
  }

  // 5. Confirm removal (unless --yes).
  if (options.yes !== true) {
    const clientList = clientsWithServer.join(", ");
    const message =
      clientsWithServer.length === 1
        ? `Remove '${name}' from ${clientsWithServer[0]}?`
        : `Remove '${name}' from ${clientList}?`;

    const confirmed = await confirm(message);
    if (!confirmed) {
      output("Removal cancelled.");
      return;
    }
  }

  // 6. Remove from each client config.
  for (const clientId of clientsWithServer) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    await adapter.removeServer(configPath, name);
  }

  // 7. Remove from store (non-fatal if already absent).
  try {
    await removeFromStore(name);
  } catch {
    // Server may not be tracked in the store — this is acceptable.
  }

  // 8. Report success.
  const removed = clientsWithServer.join(", ");
  output(`Removed '${name}' from ${removed}.`);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import chalk from "chalk";
import { detectInstalledClients as _detectClients } from "../config/detector.js";
import { getConfigPath as _getConfigPath } from "../config/paths.js";
import { removeInstalledServer as _removeFromStore } from "../store/servers.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { createConfirm } from "../utils/confirm.js";
import { stdoutOutput } from "../utils/output.js";

export function registerRemoveCommand(program: Command): void {
  program
    .command("remove <name>")
    .description("Remove an MCP server from client config(s)")
    .option("-y, --yes", "skip confirmation prompt")
    .option("-c, --client <id>", "only remove from this specific client")
    .action(async (name: string, options: RemoveOptions) => {
      const deps: RemoveDeps = {
        detectClients: _detectClients,
        getAdapter: getAdapterDefault,
        getConfigPath: _getConfigPath,
        removeFromStore: _removeFromStore,
        confirm: createConfirm(),
        output: stdoutOutput,
      };

      try {
        await removeHandler(name, options, deps);
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
