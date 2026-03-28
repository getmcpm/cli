/**
 * Async generator for cursor-based pagination over the MCP Registry API.
 *
 * Usage:
 *   for await (const entry of paginateServers(client, "filesystem")) {
 *     console.log(entry.server.name);
 *   }
 *
 * Safety: maxPages defaults to 100 to prevent infinite loops if the API
 * returns a nextCursor indefinitely (e.g., a bug on the server side).
 */

import type { RegistryClient } from "./client.js";
import type { ServerEntry } from "./types.js";

export interface PaginateOptions {
  limit?: number;
  /** Hard cap on the number of API pages fetched. Default: 100. */
  maxPages?: number;
}

export async function* paginateServers(
  client: RegistryClient,
  query: string,
  options: PaginateOptions = {}
): AsyncGenerator<ServerEntry> {
  const { limit, maxPages = 100 } = options;
  let cursor: string | undefined;
  let pagesConsumed = 0;

  while (pagesConsumed < maxPages) {
    const result = await client.searchServers(query, { limit, cursor });
    pagesConsumed += 1;

    for (const entry of result.servers) {
      // Yield a spread copy to maintain immutability
      yield { ...entry };
    }

    if (!result.metadata.nextCursor) {
      break;
    }

    cursor = result.metadata.nextCursor;
  }
}
