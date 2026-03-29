/**
 * Shared formatting helpers for McpServerEntry display.
 */

import type { McpServerEntry } from "../config/adapters/index.js";

/**
 * Returns the display string for an MCP server entry's command/URL column.
 *
 * @param entry    - The server entry to format.
 * @param fallback - String to return when neither url nor command is present.
 */
export function formatMcpEntryCommand(
  entry: McpServerEntry,
  fallback = "\u2014"
): string {
  if (entry.url) return entry.url;
  if (entry.command) {
    const args = entry.args?.join(" ") ?? "";
    return args ? `${entry.command} ${args}` : entry.command;
  }
  return fallback;
}
