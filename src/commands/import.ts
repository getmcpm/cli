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
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { formatMcpEntryCommand } from "../utils/format-entry.js";
import { stdoutOutput } from "../utils/output.js";

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
  // #23: import must run the same tier-1 trust assessment that install does,
  // so importing a pre-existing malicious config does not silently legitimize
  // it. Both are injected (matching install's deps) for full testability.
  scanTier1: (server: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
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

// ---------------------------------------------------------------------------
// Trust assessment (#23)
// ---------------------------------------------------------------------------

/**
 * Map a discovered IDE-config entry (command/args/env or url/headers) into the
 * minimal registry-shaped `ServerEntry` that the tier-1 scanner understands.
 *
 * This lets `import` reuse the exact same `scanTier1` logic `install` runs,
 * feeding the relevant config data (server name, runtime args, env var names,
 * remote URL/headers) through the scanner's pattern detectors.
 *
 * Pure — never mutates the input entry.
 */
function toServerEntry(name: string, entry: McpServerEntry): ServerEntry {
  const environmentVariables = Object.keys(entry.env ?? {}).map((key) => ({
    name: key,
  }));
  const runtimeArguments = [...(entry.args ?? [])];

  const remotes = entry.url
    ? [
        {
          type: "streamable-http",
          url: entry.url,
          headers: Object.keys(entry.headers ?? {}).map((key) => ({ name: key })),
        },
      ]
    : undefined;

  return {
    server: {
      name,
      version: "unknown",
      packages: [
        {
          registryType: "unknown",
          identifier: name,
          environmentVariables,
          runtimeArguments,
        },
      ],
      ...(remotes ? { remotes } : {}),
    },
  } as ServerEntry;
}

/**
 * Run a tier-1 trust assessment on a single discovered server. No network or
 * external scanner is used here (import is offline-only), so the score is
 * computed from static findings + neutral metadata.
 *
 * Returns both the findings and the score. The warning decision keys off the
 * findings (the genuine offline security signal) rather than the absolute
 * level: imports structurally lack a health check and registry metadata, so a
 * finding-free server still lands at "caution" — warning on level alone would
 * be noise on every import.
 */
function assessImport(
  name: string,
  entry: McpServerEntry,
  deps: ImportDeps
): { findings: Finding[]; trustScore: TrustScore } {
  const findings = deps.scanTier1(toServerEntry(name, entry));
  const input: TrustScoreInput = {
    findings,
    healthCheckPassed: null, // health check not run during import
    hasExternalScanner: false, // import is offline; tier-2 is not run
    registryMeta: {}, // imported servers have no trusted registry metadata
  };
  return { findings, trustScore: deps.computeTrustScore(input) };
}

/** Highest severity present in a findings list, or undefined when empty. */
function topSeverity(findings: Finding[]): Finding["severity"] | undefined {
  const order: Finding["severity"][] = ["critical", "high", "medium", "low"];
  return order.find((sev) => findings.some((f) => f.severity === sev));
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
    table.push([clients.join(", "), name, formatMcpEntryCommand(entry, "(no command)")]);
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

  // Import new servers — each gets a tier-1 trust assessment (#23) so that
  // importing a malicious pre-existing config does not silently legitimize it.
  const now = new Date().toISOString();
  let lowTrustCount = 0;
  for (const { name, clients, entry } of newServers) {
    const { findings, trustScore } = assessImport(name, entry, deps);

    // Warn on actual tier-1 findings (the offline security signal). The
    // absolute "level" is structurally depressed for imports (no health check,
    // no registry metadata), so warning on level alone would fire on every
    // import — see assessImport().
    const severity = topSeverity(findings);
    if (severity !== undefined) {
      lowTrustCount += 1;
      const critical = severity === "critical" || severity === "high";
      const color = critical ? chalk.red : chalk.yellow;
      const label = critical ? "WARNING" : "CAUTION";
      output(
        color(
          `${label}: "${name}" has ${findings.length} security finding` +
          `${findings.length === 1 ? "" : "s"} ` +
          `(trust ${trustScore.score}/${trustScore.maxPossible}, top severity: ${severity}). ` +
          `Review it with ${chalk.bold(`mcpm audit ${name}`)}.`
        )
      );
    }

    const server: InstalledServer = {
      name,
      version: "unknown",
      clients: [...clients],
      installedAt: now,
      trustScore: trustScore.score,
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
  if (lowTrustCount > 0) {
    output(
      chalk.yellow(
        `${lowTrustCount} imported server${lowTrustCount === 1 ? "" : "s"} ` +
        `flagged with low trust findings — review the warnings above.`
      )
    );
  }
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
      const { getAdapter } = await import("../config/index.js");
      const { getInstalledServers, addInstalledServer } = await import("../store/servers.js");
      const { readJson } = await import("../store/index.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { confirm } = await import("@inquirer/prompts");

      async function storeExists(): Promise<boolean> {
        return (await readJson<unknown>("servers.json")) !== null;
      }

      const deps: ImportDeps = {
        detectClients: detectInstalledClients,
        getAdapter,
        getConfigPath,
        getInstalledServers,
        addToStore: addInstalledServer,
        storeExists,
        confirm: (message: string) => confirm({ message }),
        output: stdoutOutput,
        scanTier1,
        computeTrustScore,
      };

      await handleImport({ yes: opts.yes, client: opts.client }, deps).catch(
        (err: Error) => {
          process.stderr.write(chalk.red(err.message) + "\n");
          process.exit(1);
        }
      );
    });
}
