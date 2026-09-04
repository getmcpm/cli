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
import { sanitizeForTerminal } from "../guard/sanitize.js";
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
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read">;
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
/** The one skip sentence. Two sinks (stderr under --json, stdout otherwise). */
function skipNotice(malformed: ReadonlyArray<{ name: string; client: ClientId }>): string {
  return (
    `${malformed.length} entr${malformed.length === 1 ? "y" : "ies"} could not be read ` +
    `and ${malformed.length === 1 ? "is" : "are"} not listed: ` +
    `${malformed.map((m) => `${sanitizeForTerminal(m.name)} (${m.client})`).join(", ")}. ` +
    `Run \`mcpm doctor\` for details.`
  );
}

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
  // #59: entries read() dropped for failing shape validation. `list` is the
  // inventory command, and --json has no stderr channel a consumer reads.
  const malformed: Array<{ name: string; client: ClientId }> = [];

  for (const clientId of clients) {
    try {
      const adapter = getAdapter(clientId);
      const configPath = getPath(clientId);
      const servers = await adapter.read(configPath, (name) => {
        if (!malformed.some((m) => m.name === name && m.client === clientId)) {
          malformed.push({ name, client: clientId });
        }
      });

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
    // #59: the skip notice goes to STDERR, not into the payload. Flipping the
    // shape from a bare array to an object only in the malformed case would
    // break `JSON.parse(out).map(...)` exactly when things are already wrong.
    // (The MCP `mcpm_list` tool puts `skipped` in its result because that
    // surface has no stderr an agent can see; the CLI does.)
    if (malformed.length > 0) process.stderr.write(`mcpm: ${skipNotice(malformed)}\n`);
    output(JSON.stringify(jsonData, null, 2));
    return;
  }

  if (malformed.length > 0) output(chalk.yellow(skipNotice(malformed)));

  // No servers found.
  if (rows.length === 0) {
    output(
      malformed.length > 0
        ? "No readable MCP servers installed."
        : "No MCP servers installed. Try: mcpm search <query>"
    );
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
    .option("--client <id>", "Filter output to a single client (claude-desktop, claude-code, cursor, vscode, windsurf, gemini-cli)")
    .option("--json", "Output raw JSON instead of a formatted table")
    .action(async (opts: { client?: string; json?: boolean }) => {
      const { detectInstalledClients, getConfigPath, getAdapter } = await import("../config/index.js");

      await handleList(
        { client: opts.client, json: opts.json },
        {
          detectClients: detectInstalledClients,
          getAdapter,
          getPath: getConfigPath,
          output: stdoutOutput,
        }
      );
    });
}
