/**
 * Tracks installed MCP servers in ~/.mcpm/servers.json.
 */

import { readJson, writeJson } from "./index.js";
import type { ClientId } from "../config/paths.js";

const FILENAME = "servers.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface InstalledServer {
  name: string;
  version: string;
  clients: ClientId[];
  installedAt: string; // ISO 8601 timestamp
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/**
 * Returns all installed servers. Returns an empty array if none are stored.
 * Each call returns a fresh array.
 */
export async function getInstalledServers(): Promise<InstalledServer[]> {
  const data = await readJson<InstalledServer[]>(FILENAME);
  return data === null ? [] : [...data];
}

/**
 * Appends a server to the installed list. Does not mutate the input object.
 */
export async function addInstalledServer(
  server: InstalledServer
): Promise<void> {
  const current = await getInstalledServers();
  const updated: InstalledServer[] = [...current, { ...server }];
  await writeJson(FILENAME, updated);
}

/**
 * Removes a server by name. Throws if the server is not found.
 */
export async function removeInstalledServer(name: string): Promise<void> {
  const current = await getInstalledServers();
  const index = current.findIndex((s) => s.name === name);

  if (index === -1) {
    throw new Error(`Server "${name}" not found in installed servers list.`);
  }

  const updated = current.filter((s) => s.name !== name);
  await writeJson(FILENAME, updated);
}
