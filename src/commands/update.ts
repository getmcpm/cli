/**
 * `mcpm update` command — check for newer versions and update installed servers.
 *
 * Exports:
 * - handleUpdate() — pure handler with injectable deps for testing
 * - registerUpdateCommand() — registers the command on a Commander program
 *
 * Architecture:
 * - "Update" means: re-fetch registry metadata, compare version, update store record.
 * - For npm servers (npx -y package), the actual binary is fetched at runtime —
 *   so update mainly updates the stored version record and re-runs trust assessment.
 * - Registry unavailability is graceful — skip that server with an error note.
 * - All external deps are injectable for hermetic testing.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import type { InstalledServer } from "../store/servers.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter } from "../config/adapters/index.js";
import { levelColor, extractRegistryMeta } from "../utils/format-trust.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UpdateOptions {
  yes?: boolean;
  json?: boolean;
}

export interface UpdateDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  addInstalledServer: (server: InstalledServer) => Promise<void>;
  removeInstalledServer: (name: string) => Promise<void>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  confirm: (message: string) => Promise<boolean>;
  output: (text: string) => void;
}

interface UpdateResult {
  name: string;
  oldVersion: string;
  newVersion: string;
  updated: boolean;
  trustScore?: TrustScore;
  error?: string;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm update`.
 */
export async function handleUpdate(
  options: UpdateOptions,
  deps: UpdateDeps
): Promise<void> {
  const {
    getInstalledServers,
    getServer,
    addInstalledServer,
    removeInstalledServer,
    scanTier1,
    computeTrustScore,
    confirm,
    output,
  } = deps;

  const servers = await getInstalledServers();

  if (servers.length === 0) {
    output("No servers installed.");
    return;
  }

  const spinner = ora({ text: "Checking for updates...", isSilent: !process.stdout.isTTY }).start();

  // Fetch current metadata from registry for all servers
  const results: UpdateResult[] = [];

  for (const installed of servers) {
    let entry: ServerEntry;
    try {
      entry = await getServer(installed.name);
    } catch {
      results.push({
        name: installed.name,
        oldVersion: installed.version,
        newVersion: installed.version,
        updated: false,
        error: "Registry unavailable — could not fetch metadata",
      });
      continue;
    }

    const newVersion = entry.server.version;
    const hasUpdate = newVersion !== installed.version;

    results.push({
      name: installed.name,
      oldVersion: installed.version,
      newVersion,
      updated: false,
      trustScore: hasUpdate ? undefined : undefined,
      error: undefined,
    });

    // Store the entry for later reference (used in update flow)
    const lastResult = results[results.length - 1];
    // Attach entry reference using a closure capture below
    if (hasUpdate) {
      // Tag this result so we know it has an update
      (lastResult as UpdateResult & { _entry?: ServerEntry })._entry = entry;
    }
  }

  spinner.stop();

  // Filter to those with updates available
  const withUpdates = results.filter((r) => r.newVersion !== r.oldVersion && !r.error);

  const isJson = options.json === true;

  // Show registry errors (non-JSON mode only)
  if (!isJson) {
    for (const r of results.filter((r) => r.error)) {
      output(chalk.yellow(`  ${r.name}: ${r.error}`));
    }
  }

  if (withUpdates.length === 0) {
    if (!isJson) {
      // Show up-to-date message unless all were errors
      if (results.filter((r) => !r.error).length > 0) {
        output(chalk.green("All servers are up to date."));
      }
    } else {
      output(
        JSON.stringify(
          results.map((r) => ({
            name: r.name,
            oldVersion: r.oldVersion,
            newVersion: r.newVersion,
            updated: false,
            error: r.error ?? null,
          })),
          null,
          2
        )
      );
    }
    return;
  }

  // Show available updates (non-JSON mode)
  if (!isJson) {
    output(chalk.bold("\nUpdates available:"));
    for (const r of withUpdates) {
      output(`  ${chalk.white(r.name)}: ${chalk.yellow(r.oldVersion)} → ${chalk.green(r.newVersion)}`);
    }
  }

  // Prompt for confirmation (unless --yes)
  if (options.yes !== true) {
    const confirmed = await confirm(
      `Update ${withUpdates.length} server${withUpdates.length !== 1 ? "s" : ""}?`
    );
    if (!confirmed) {
      if (!isJson) {
        output("Update cancelled — skipping all updates.");
      } else {
        output(
          JSON.stringify(
            results.map((r) => ({ name: r.name, oldVersion: r.oldVersion, newVersion: r.newVersion, updated: false })),
            null,
            2
          )
        );
      }
      return;
    }
  }

  // Track update outcomes immutably (name → { updated, trustScore })
  const updateOutcomes = new Map<string, { updated: boolean; trustScore: TrustScore }>();

  // Perform updates
  for (const r of withUpdates) {
    const resultWithEntry = r as UpdateResult & { _entry?: ServerEntry };
    const entry = resultWithEntry._entry;

    if (!entry) continue;

    // Run trust assessment on new version
    const tier1Findings = scanTier1(entry);
    const trustScore = computeTrustScore({
      findings: tier1Findings,
      healthCheckPassed: null,
      hasExternalScanner: false,
      registryMeta: {
        ...extractRegistryMeta(entry),
        downloadCount: undefined,
      },
    });

    // Update store: remove old, add new
    try {
      await removeInstalledServer(r.name);
    } catch {
      // Server may not be in store — non-fatal
    }

    // Preserve original clients from installed server list
    const originalInstalled = (await deps.getInstalledServers().catch(() => [])) as InstalledServer[];
    const original = originalInstalled.find((s) => s.name === r.name);
    const finalRecord: InstalledServer = {
      name: r.name,
      version: r.newVersion,
      clients: original?.clients ?? [],
      installedAt: new Date().toISOString(),
    };

    await addInstalledServer(finalRecord);

    // Record outcome immutably instead of mutating the result object
    updateOutcomes.set(r.name, { updated: true, trustScore });

    if (!isJson) {
      output(
        `  ${chalk.green("✓")} Updated ${chalk.white(r.name)} to ${chalk.green(r.newVersion)} [${levelColor(trustScore.level)}]`
      );
    }
  }

  if (isJson) {
    output(
      JSON.stringify(
        results.map((r) => {
          const outcome = updateOutcomes.get(r.name);
          return {
            name: r.name,
            oldVersion: r.oldVersion,
            newVersion: r.newVersion,
            updated: outcome?.updated ?? r.updated,
            trustScore: outcome?.trustScore ?? r.trustScore ?? null,
            error: r.error ?? null,
          };
        }),
        null,
        2
      )
    );
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerUpdateCommand(program: Command): void {
  program
    .command("update")
    .description("Check for newer versions and update installed servers")
    .option("-y, --yes", "Skip confirmation prompt")
    .option("--json", "Output raw JSON")
    .action(async (opts: { yes?: boolean; json?: boolean }) => {
      const { getInstalledServers, addInstalledServer, removeInstalledServer } =
        await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { getAdapter: getAdapterDefault, getConfigPath } = await import("../config/index.js");
      const { createConfirm } = await import("../utils/confirm.js");

      const client = new RegistryClient();

      const deps: UpdateDeps = {
        getInstalledServers,
        getServer: (name) => client.getServer(name),
        addInstalledServer,
        removeInstalledServer,
        getAdapter: getAdapterDefault,
        getConfigPath,
        scanTier1,
        computeTrustScore,
        confirm: createConfirm(),
        output: (text) => process.stdout.write(text + "\n"),
      };

      await handleUpdate({ yes: opts.yes, json: opts.json }, deps).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
