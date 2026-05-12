/**
 * Tracks installed MCP servers in ~/.mcpm/servers.json.
 */

import { readJson, writeJson } from "./index.js";
import type { ClientId } from "../config/paths.js";

const FILENAME = "servers.json";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export const SERVERS_SCHEMA_VERSION = 2;

export interface InstalledServer {
  name: string;
  version: string;
  clients: ClientId[];
  installedAt: string; // ISO 8601 timestamp
  trustScore?: number;  // stored at install/update time for drift detection
}

interface ServersFile {
  mcpmSchemaVersion: number;
  servers: InstalledServer[];
}

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

/**
 * Returns all installed servers. Returns an empty array if none are stored.
 * Handles both legacy array format (schema v1) and current object format (v2).
 * Each call returns a fresh array.
 */
export async function getInstalledServers(): Promise<InstalledServer[]> {
  const raw = await readJson<InstalledServer[] | ServersFile>(FILENAME);
  if (raw === null) return [];
  // Legacy format: bare array (schema v1)
  if (Array.isArray(raw)) return [...raw];
  return [...raw.servers];
}

function buildFile(servers: InstalledServer[]): ServersFile {
  return { mcpmSchemaVersion: SERVERS_SCHEMA_VERSION, servers };
}

/**
 * Appends a server to the installed list. Does not mutate the input object.
 */
export async function addInstalledServer(
  server: InstalledServer
): Promise<void> {
  const current = await getInstalledServers();
  await writeJson(FILENAME, buildFile([...current, { ...server }]));
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

  await writeJson(FILENAME, buildFile(current.filter((s) => s.name !== name)));
}
