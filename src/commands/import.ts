/**
 * `mcpm import` command — detect existing MCP server configs and offer to import them.
 *
 * Exports:
 * - handleImport()   — pure handler with injectable deps for testing
 * - checkFirstRun()  — first-run hint (called from main entry point)
 * - registerImportCommand() — registers the command on a Commander program
 *
 * Architecture:
 * - All external I/O is injected via ImportDeps for full testability.
 * - Servers with the same name across multiple clients are de-duplicated into one
 *   InstalledServer entry whose `clients` array lists all clients.
 * - Immutable patterns used throughout — no mutation of input objects.
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { InstalledServer } from "../store/servers.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ImportOptions {
  yes?: boolean;
  client?: string;
}

export interface ImportDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  getInstalledServers: () => Promise<InstalledServer[]>;
  addToStore: (server: InstalledServer) => Promise<void>;
  storeExists: () => Promise<boolean>;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * A collected server entry with its source client.
 */
interface DiscoveredServer {
  readonly name: string;
  readonly clientId: ClientId;
  readonly entry: McpServerEntry;
}

/**
 * Reads servers from a single client adapter, swallowing errors so that one
 * broken config file doesn't prevent processing the rest.
 */
async function readClientServers(
  clientId: ClientId,
  deps: ImportDeps
): Promise<DiscoveredServer[]> {
  try {
    const adapter = deps.getAdapter(clientId);
    const configPath = deps.getConfigPath(clientId);
    const servers = await adapter.read(configPath);
    return Object.entries(servers).map(([name, entry]) => ({
      name,
      clientId,
      entry: { ...entry },
    }));
  } catch {
    return [];
  }
}

/**
 * Collects all servers from the given clients and de-duplicates by server name.
 * If the same server name appears in multiple clients, a single entry is returned
 * with all client IDs in its `clients` array.
 */
function deduplicateServers(discovered: DiscoveredServer[]): Array<{
  name: string;
  clients: ClientId[];
  entry: McpServerEntry;
}> {
  const map = new Map<string, { clients: ClientId[]; entry: McpServerEntry }>();

  for (const { name, clientId, entry } of discovered) {
    const existing = map.get(name);
    if (existing) {
      // Immutable update — create a new clients array
      map.set(name, {
        clients: [...existing.clients, clientId],
        entry: existing.entry,
      });
    } else {
      map.set(name, { clients: [clientId], entry: { ...entry } });
    }
  }

  return Array.from(map.entries()).map(([name, val]) => ({
    name,
    clients: val.clients,
    entry: val.entry,
  }));
}

/**
 * Returns the display string for a server entry's command/URL column.
 */
function formatCommandOrUrl(entry: McpServerEntry): string {
  if (entry.url) {
    return entry.url;
  }
  if (entry.command) {
    const argsStr = entry.args && entry.args.length > 0 ? ` ${entry.args.join(" ")}` : "";
    return `${entry.command}${argsStr}`;
  }
  return "(no command)";
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm import`.
 */
export async function handleImport(
  options: ImportOptions,
  deps: ImportDeps
): Promise<void> {
  const { output } = deps;

  // Determine which clients to scan
  const allClients = await deps.detectClients();
  const clientsToScan: ClientId[] = options.client
    ? ([options.client] as ClientId[]).filter((c) => allClients.includes(c))
    : allClients;

  if (options.client && clientsToScan.length === 0) {
    throw new Error(`Client "${options.client}" is not installed on this machine.`);
  }

  // Read servers from each client — in parallel
  const perClientResults = await Promise.all(
    clientsToScan.map((clientId) => readClientServers(clientId, deps))
  );
  const discovered: DiscoveredServer[] = perClientResults.flat();

  // De-duplicate by server name
  const uniqueServers = deduplicateServers(discovered);

  if (uniqueServers.length === 0) {
    output(chalk.yellow("No existing MCP servers found in any client config."));
    return;
  }

  // Display table
  const table = new Table({
    head: [chalk.bold("Client"), chalk.bold("Server Name"), chalk.bold("Command / URL")],
    style: { head: ["cyan"] },
  });

  for (const { name, clients, entry } of uniqueServers) {
    table.push([clients.join(", "), name, formatCommandOrUrl(entry)]);
  }

  output(table.toString());
  output("");

  // Determine which are already tracked
  const installedServers = await deps.getInstalledServers();
  const trackedNames = new Set(installedServers.map((s) => s.name));
  const newServers = uniqueServers.filter((s) => !trackedNames.has(s.name));
  const alreadyTrackedCount = uniqueServers.length - newServers.length;

  const totalCount = uniqueServers.length;
  const promptMessage =
    `Import ${totalCount} server${totalCount === 1 ? "" : "s"} into mcpm management? ` +
    `This lets mcpm track, audit, and update them.`;

  // Confirm (skip if --yes)
  let shouldImport = options.yes ?? false;
  if (!shouldImport) {
    shouldImport = await deps.confirm(promptMessage);
  }

  if (!shouldImport) {
    output(chalk.yellow("Import cancelled. No changes made."));
    return;
  }

  // Import new servers
  const now = new Date().toISOString();
  for (const { name, clients, entry: _entry } of newServers) {
    const server: InstalledServer = {
      name,
      version: "unknown",
      clients: [...clients],
      installedAt: now,
    };
    await deps.addToStore(server);
  }

  const importedCount = newServers.length;
  output(
    chalk.green(
      `Imported ${importedCount} server${importedCount === 1 ? "" : "s"}. ` +
      `Skipped ${alreadyTrackedCount} already tracked.`
    )
  );
}

// ---------------------------------------------------------------------------
// First-run detection
// ---------------------------------------------------------------------------

/**
 * Check if this is the first run (store doesn't exist yet).
 * If so, scan clients for existing MCP servers and show a hint.
 * Does NOT auto-import — just shows the hint.
 */
export async function checkFirstRun(deps: ImportDeps): Promise<void> {
  // If the store already exists, this is not the first run
  const exists = await deps.storeExists();
  if (exists) {
    return;
  }

  // Detect clients and count servers
  const clients = await deps.detectClients();
  if (clients.length === 0) {
    return;
  }

  const perClientResults = await Promise.all(
    clients.map((clientId) => readClientServers(clientId, deps))
  );
  const discovered: DiscoveredServer[] = perClientResults.flat();

  const uniqueServers = deduplicateServers(discovered);
  if (uniqueServers.length === 0) {
    return;
  }

  const count = uniqueServers.length;
  deps.output(
    chalk.cyan(
      `I see you have ${count} MCP server${count === 1 ? "" : "s"} configured. ` +
      `Run ${chalk.bold("mcpm import")} to manage them with mcpm.`
    )
  );
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerImportCommand(program: Command): void {
  program
    .command("import")
    .description("Detect existing MCP server configs and import them into mcpm management")
    .option("-y, --yes", "Skip confirmation prompt")
    .option("-c, --client <id>", "Only import from this specific client")
    .action(async (opts: { yes?: boolean; client?: string }) => {
      const { detectInstalledClients } = await import("../config/detector.js");
      const { getConfigPath } = await import("../config/paths.js");
      const {
        ClaudeDesktopAdapter,
        CursorAdapter,
        VSCodeAdapter,
        WindsurfAdapter,
      } = await import("../config/index.js");
      const { getInstalledServers, addInstalledServer } = await import("../store/servers.js");
      const { readJson } = await import("../store/index.js");
      const { confirm } = await import("@inquirer/prompts");
      const path = await import("path");
      const os = await import("os");

      function getAdapter(clientId: ClientId): ConfigAdapter {
        switch (clientId) {
          case "claude-desktop": return new ClaudeDesktopAdapter();
          case "cursor": return new CursorAdapter();
          case "vscode": return new VSCodeAdapter();
          case "windsurf": return new WindsurfAdapter();
          default: throw new Error(`Unknown clientId: ${String(clientId)}`);
        }
      }

      async function storeExists(): Promise<boolean> {
        const storePath = path.join(os.homedir(), ".mcpm", "servers.json");
        const data = await readJson<unknown>("servers.json");
        void storePath;
        return data !== null;
      }

      const deps: ImportDeps = {
        detectClients: detectInstalledClients,
        getAdapter,
        getConfigPath,
        getInstalledServers,
        addToStore: addInstalledServer,
        storeExists,
        confirm: (message: string) => confirm({ message }),
        output: (text: string) => process.stdout.write(text + "\n"),
      };

      await handleImport({ yes: opts.yes, client: opts.client }, deps).catch(
        (err: Error) => {
          process.stderr.write(chalk.red(err.message) + "\n");
          process.exit(1);
        }
      );
    });
}
