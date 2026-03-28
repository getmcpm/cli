/**
 * Detects which AI clients are installed by checking whether their config
 * files are accessible on the current machine.
 */

import { access } from "fs/promises";
import { CLIENT_IDS, getConfigPath } from "./paths.js";
import type { ClientId } from "./paths.js";

/**
 * Returns the list of client IDs whose config files exist and are accessible.
 * Clients with inaccessible or non-existent config files are excluded.
 *
 * Always returns a fresh array — callers may mutate their copy safely.
 */
export async function detectInstalledClients(): Promise<ClientId[]> {
  const results = await Promise.all(
    CLIENT_IDS.map(async (clientId) => {
      try {
        await access(getConfigPath(clientId));
        return clientId;
      } catch {
        return null;
      }
    })
  );

  return results.filter((id): id is ClientId => id !== null);
}
