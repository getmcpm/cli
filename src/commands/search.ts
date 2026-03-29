/**
 * search command — searches the MCP registry for servers matching a query.
 *
 * Exports:
 * - handleSearch() — pure handler function with injectable dependencies for testing
 * - registerSearch() — registers the command on a Commander program
 *
 * Architecture:
 * - All formatting (chalk, cli-table3) is done inside handleSearch.
 * - No console.log — output is routed through deps.output() for testability.
 * - Spinner is created but silenced in test environments (no TTY).
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import ora from "ora";
import type { RegistryClient } from "../registry/client.js";
import type { ServerEntry } from "../registry/types.js";
import { OFFICIAL_META_KEY } from "../utils/format-trust.js";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SearchOptions {
  limit?: number;
  json?: boolean;
}

export interface SearchDeps {
  registryClient: Pick<RegistryClient, "searchServers">;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Transport resolver — pure function
// ---------------------------------------------------------------------------

/**
 * Determines the transport label for a server entry to display in the table.
 * Priority: first package registryType → remote type → "-" (unknown).
 */
function resolveTransport(entry: ServerEntry): string {
  const server = entry.server;

  if (server.packages.length > 0) {
    const type = server.packages[0].registryType;
    // Normalise "oci" (Docker Hub) to the user-visible "docker" label.
    return type === "oci" ? "docker" : type;
  }

  if (server.remotes && server.remotes.length > 0) {
    return "http";
  }

  return "-";
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm search <query>`.
 * Dependencies are injected so the function is hermetically testable.
 */
export async function handleSearch(
  query: string,
  options: SearchOptions,
  deps: SearchDeps
): Promise<void> {
  const { registryClient, output } = deps;
  const limit = options.limit ?? 20;

  const spinner = ora({ text: "Searching...", isSilent: !process.stdout.isTTY }).start();

  let result;
  try {
    result = await registryClient.searchServers(query, { limit, version: "latest" });
  } catch (err) {
    spinner.stop();
    throw err;
  }

  spinner.stop();

  const entries = result.servers;

  // --json flag: output raw JSON array and return early.
  if (options.json === true) {
    const jsonData = entries.map((e) => ({
      name: e.server.name,
      description: e.server.description ?? null,
      version: e.server.version,
      transport: resolveTransport(e),
      status: e._meta?.[OFFICIAL_META_KEY]?.status ?? null,
    }));
    output(JSON.stringify(jsonData, null, 2));
    return;
  }

  // No results.
  if (entries.length === 0) {
    output(`No servers found for '${query}'`);
    return;
  }

  // Build table.
  const table = new Table({
    head: [
      chalk.cyan("Name"),
      chalk.cyan("Description"),
      chalk.cyan("Version"),
      chalk.cyan("Transport"),
      chalk.cyan("Trust Score"),
    ],
    style: { head: [], border: [] },
    wordWrap: true,
    colWidths: [40, 40, 12, 12, 12],
  });

  for (const entry of entries) {
    const { server, _meta } = entry;
    const official = _meta?.[OFFICIAL_META_KEY] ?? {};
    const transport = resolveTransport(entry);
    const trustScore = official?.status === "active" ? chalk.green("active") : (official?.status ?? "-");
    const description = server.description ?? "";

    table.push([
      chalk.white(server.name),
      description,
      server.version,
      transport,
      trustScore,
    ]);
  }

  output(table.toString());
}

// ---------------------------------------------------------------------------
// Command registration
// ---------------------------------------------------------------------------

/**
 * Registers the `search <query>` command on the given Commander program.
 * Uses a real RegistryClient and process.stdout for production use.
 */
export function registerSearch(program: Command): void {
  program
    .command("search <query>")
    .description("Search the MCP registry for servers")
    .option("-l, --limit <n>", "Maximum number of results to return", "20")
    .option("--json", "Output raw JSON instead of a formatted table")
    .action(async (query: string, opts: { limit: string; json?: boolean }) => {
      // Lazy-import to avoid circular dependencies and allow tree-shaking.
      const { RegistryClient } = await import("../registry/client.js");
      const client = new RegistryClient();
      await handleSearch(
        query,
        { limit: parseInt(opts.limit, 10), json: opts.json },
        { registryClient: client, output: stdoutOutput }
      );
    });
}
