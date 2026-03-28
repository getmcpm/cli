/**
 * ConfigAdapter interface and McpServerEntry type.
 *
 * Each supported AI client has a concrete adapter that implements this
 * interface. Adapters handle all config file I/O, including atomic writes
 * and key-name differences between clients.
 */

import type { ClientId } from "../paths.js";

/**
 * A single MCP server entry as stored in a client config file.
 * Supports both stdio (command/args) and HTTP (url/headers) transport formats.
 */
export interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
}

/**
 * Common interface for all client config adapters.
 *
 * Adapters MUST:
 * - Preserve unmanaged keys in the config file (read-modify-write).
 * - Use atomic writes: write to a .tmp file then rename.
 * - Return new objects — never mutate inputs.
 * - Throw descriptive errors for "already exists" and "not found" cases.
 */
export interface ConfigAdapter {
  readonly clientId: ClientId;

  /** Read all MCP server entries from the config file. */
  read(configPath: string): Promise<Record<string, McpServerEntry>>;

  /**
   * Add a new server entry. Throws if the server name already exists.
   * Creates the file (with correct structure) if it does not exist.
   */
  addServer(
    configPath: string,
    name: string,
    entry: McpServerEntry
  ): Promise<void>;

  /** Remove a server entry. Throws if the server name is not found. */
  removeServer(configPath: string, name: string): Promise<void>;

  /** Convenience alias — returns same result as read(). */
  listServers(configPath: string): Promise<Record<string, McpServerEntry>>;
}
