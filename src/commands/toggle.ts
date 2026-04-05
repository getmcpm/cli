/**
 * Shared handler for `mcpm disable` and `mcpm enable`.
 *
 * Both commands toggle the `disabled` flag on server entries across client
 * configs. This module eliminates the duplication between them by
 * parameterising the toggle direction.
 */

import type { ClientId } from "../config/paths.js";
import { CLIENT_IDS } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ToggleDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

export interface ToggleOptions {
  client?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleToggleServer(
  name: string,
  disabled: boolean,
  options: ToggleOptions,
  deps: ToggleDeps
): Promise<void> {
  const { detectClients, getAdapter, getConfigPath, output } = deps;
  const action = disabled ? "Disabled" : "Enabled";
  const alreadyState = disabled ? "disabled" : "enabled";

  let clients = await detectClients();

  if (options.client !== undefined) {
    if (!CLIENT_IDS.includes(options.client as ClientId)) {
      throw new Error(
        `Unknown client "${options.client}". Valid values: ${CLIENT_IDS.join(", ")}.`
      );
    }
    const target = options.client as ClientId;
    if (!clients.includes(target)) {
      throw new Error(`Client "${target}" is not installed on this machine.`);
    }
    clients = [target];
  }

  // Single-pass: read each client config once, classify into buckets.
  const alreadyDone: ClientId[] = [];
  const toToggle: Array<{ clientId: ClientId; configPath: string }> = [];

  for (const clientId of clients) {
    const adapter = getAdapter(clientId);
    const configPath = getConfigPath(clientId);
    const servers: Record<string, McpServerEntry> = await adapter.read(configPath);

    if (!Object.prototype.hasOwnProperty.call(servers, name)) {
      continue;
    }

    const isCurrentlyDisabled = servers[name].disabled === true;
    if (isCurrentlyDisabled === disabled) {
      alreadyDone.push(clientId);
    } else {
      toToggle.push({ clientId, configPath });
    }
  }

  if (alreadyDone.length === 0 && toToggle.length === 0) {
    const scope = options.client ? `client "${options.client}"` : "any client config";
    throw new Error(`Server '${name}' not found in ${scope}.`);
  }

  if (toToggle.length === 0) {
    output(`Server '${name}' is already ${alreadyState} in ${alreadyDone.join(", ")}.`);
    return;
  }

  for (const { clientId, configPath } of toToggle) {
    const adapter = getAdapter(clientId);
    await adapter.setServerDisabled(configPath, name, disabled);
  }

  const toggledIds = toToggle.map((t) => t.clientId);
  output(`${action} '${name}' in ${toggledIds.join(", ")}.`);
}
