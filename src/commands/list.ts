/**
 * list command — shows all installed MCP servers across detected AI clients.
 *
 * Exports:
 * - handleList() — pure handler function with injectable dependencies for testing
 * - registerList() — registers the command on a Commander program
 *
 * Architecture:
 * - READ-ONLY: never calls the registry API, never mutates any config file.
 * - All I/O dependencies (detectInstalledClients, adapters, paths) are injected.
 * - No console.log — all output routed through deps.output() for testability.
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import { formatMcpEntryCommand } from "../utils/format-entry.js";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ListOptions {
  client?: string;
  json?: boolean;
}

export interface ListDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read" | "addServer" | "removeServer">;
  getPath: (clientId: ClientId) => string;
  output: (text: string) => void;
}

interface ServerRow {
  client: ClientId;
  serverName: string;
  entry: McpServerEntry;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm list`.
 * All dependencies are injected so the function is hermetically testable.
 * This command is strictly READ-ONLY — it never writes to any config file.
 */
export async function handleList(
  options: ListOptions,
  deps: ListDeps
): Promise<void> {
  const { detectClients, getAdapter, getPath, output } = deps;

  const allClients = await detectClients();

  // Apply --client filter if specified.
  const clients: ClientId[] = options.client
    ? allClients.filter((id) => id === options.client)
    : allClients;

  // Collect rows from all applicable clients.
  const rows: ServerRow[] = [];

  for (const clientId of clients) {
    try {
      const adapter = getAdapter(clientId);
      const configPath = getPath(clientId);
      const servers = await adapter.read(configPath);

      for (const [serverName, entry] of Object.entries(servers)) {
        rows.push({ client: clientId, serverName, entry: { ...entry } });
      }
    } catch {
      // Skip clients with malformed or unreadable configs
    }
  }

  // --json flag: output raw JSON array and return early.
  if (options.json === true) {
    const jsonData = rows.map(({ client, serverName, entry }) => ({
      client,
      serverName,
      entry,
    }));
    output(JSON.stringify(jsonData, null, 2));
    return;
  }

  // No servers found.
  if (rows.length === 0) {
    output("No MCP servers installed. Try: mcpm search <query>");
    return;
  }

  // Build table.
  const table = new Table({
    head: [
      chalk.cyan("Client"),
      chalk.cyan("Server Name"),
      chalk.cyan("Status"),
      chalk.cyan("Command/URL"),
    ],
    style: { head: [], border: [] },
    wordWrap: true,
    colWidths: [18, 28, 10, 42],
  });

  for (const { client, serverName, entry } of rows) {
    const status = entry.disabled ? chalk.yellow("disabled") : chalk.green("active");
    table.push([
      chalk.yellow(client),
      chalk.white(serverName),
      status,
      chalk.dim(formatMcpEntryCommand(entry)),
    ]);
  }

  output(table.toString());
}

// ---------------------------------------------------------------------------
// Command registration
// ---------------------------------------------------------------------------

/**
 * Registers the `list` command on the given Commander program.
 */
export function registerList(program: Command): void {
  program
    .command("list")
    .description("List all installed MCP servers across detected AI clients")
    .option("--client <id>", "Filter output to a single client (claude-desktop, cursor, vscode, windsurf)")
    .option("--json", "Output raw JSON instead of a formatted table")
    .action(async (opts: { client?: string; json?: boolean }) => {
      const { detectInstalledClients } = await import("../config/detector.js");
      const { getConfigPath } = await import("../config/paths.js");
      const { ClaudeDesktopAdapter } = await import("../config/adapters/claude-desktop.js");
      const { CursorAdapter } = await import("../config/adapters/cursor.js");
      const { VSCodeAdapter } = await import("../config/adapters/vscode.js");
      const { WindsurfAdapter } = await import("../config/adapters/windsurf.js");

      const adapterMap = new Map<ClientId, ConfigAdapter>([
        ["claude-desktop", new ClaudeDesktopAdapter()],
        ["cursor", new CursorAdapter()],
        ["vscode", new VSCodeAdapter()],
        ["windsurf", new WindsurfAdapter()],
      ]);

      await handleList(
        { client: opts.client, json: opts.json },
        {
          detectClients: detectInstalledClients,
          getAdapter: (clientId) => adapterMap.get(clientId) as ConfigAdapter,
          getPath: getConfigPath,
          output: stdoutOutput,
        }
      );
    });
}
