/**
 * `mcpm audit` command — scan all installed servers and produce a trust report.
 *
 * Exports:
 * - handleAudit() — pure handler with injectable deps for testing
 * - registerAuditCommand() — registers the command on a Commander program
 *
 * Architecture:
 * - All external deps (store, registry, scanner) are injectable.
 * - Tier 2 scanner availability is checked once, not per server.
 * - Registry unavailability is graceful — the server is skipped with a note.
 * - Returns exit code: 0 if all safe/caution, 1 if any risky.
 * - --fix: removes servers below trust threshold; returns 0 if all risky removed.
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import ora from "ora";
import type { InstalledServer } from "../store/servers.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { levelColor, scoreBar, extractRegistryMeta } from "../utils/format-trust.js";
import { stdoutOutput } from "../utils/output.js";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter } from "../config/adapters/index.js";
import { parseMinTrust } from "./install.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_FIX_THRESHOLD = 50;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditOptions {
  json?: boolean;
  fix?: boolean;
  minTrust?: number;
  yes?: boolean;
}

export interface AuditDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  scanTier1: (entry: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  output: (text: string) => void;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "removeServer">;
  getConfigPath: (clientId: ClientId) => string;
  removeFromStore: (name: string) => Promise<void>;
  confirm: (message: string) => Promise<boolean>;
}

interface AuditResult {
  name: string;
  installedServer: InstalledServer;
  score: TrustScore;
  findings: Finding[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Fix step
// ---------------------------------------------------------------------------

interface FixOutcome {
  threshold: number;
  removed: string[];
  failed: string[];
}

async function runFix(
  results: AuditResult[],
  options: AuditOptions,
  deps: AuditDeps
): Promise<FixOutcome> {
  const { getAdapter, getConfigPath, removeFromStore, confirm, output } = deps;
  const threshold = options.minTrust ?? DEFAULT_FIX_THRESHOLD;

  // Build candidates: results without registry errors where score is below threshold
  const candidates = results.filter(
    (r) => r.error === undefined && r.score.score < threshold
  );

  if (candidates.length === 0) {
    output(chalk.green("Nothing to fix — all servers meet the trust threshold."));
    return { threshold, removed: [], failed: [] };
  }

  // Display candidates
  output(
    chalk.yellow(
      `\n${candidates.length} server${candidates.length !== 1 ? "s" : ""} below trust threshold (${threshold}):`
    )
  );
  for (const c of candidates) {
    output(`  ${chalk.white(c.name)} — score ${c.score.score}/${c.score.maxPossible}`);
  }

  // Confirmation gate (skip if --yes)
  if (options.yes !== true) {
    const confirmed = await confirm(
      `Remove ${candidates.length} server${candidates.length !== 1 ? "s" : ""}?`
    );
    if (!confirmed) {
      output("Fix cancelled.");
      return { threshold, removed: [], failed: [] };
    }
  }

  const removed: string[] = [];
  const failed: string[] = [];

  // Per-server, per-client removal loop with isolated error handling
  for (const candidate of candidates) {
    const clientIds = candidate.installedServer.clients as ClientId[];
    let anyClientSucceeded = false;
    const clientFailures: string[] = [];

    for (const clientId of clientIds) {
      try {
        const adapter = getAdapter(clientId);
        const configPath = getConfigPath(clientId);
        await adapter.removeServer(configPath, candidate.name);
        anyClientSucceeded = true;
      } catch {
        clientFailures.push(clientId);
      }
    }

    if (anyClientSucceeded) {
      await removeFromStore(candidate.name);
      removed.push(candidate.name);
      if (clientFailures.length > 0) {
        failed.push(
          `${candidate.name} (failed clients: ${clientFailures.join(", ")})`
        );
      }
    } else {
      failed.push(candidate.name);
    }
  }

  // Report results
  if (removed.length > 0) {
    output(chalk.green(`\nRemoved ${removed.length} server${removed.length !== 1 ? "s" : ""}: ${removed.join(", ")}`));
  }
  if (failed.length > 0) {
    output(chalk.red(`Failed to fully remove ${failed.length} server${failed.length !== 1 ? "s" : ""}: ${failed.join(", ")}`));
  }

  return { threshold, removed, failed };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm audit`.
 * Returns exit code: 0 if all safe/caution (or --fix removes all risky), 1 if any risky remain.
 */
export async function handleAudit(
  options: AuditOptions,
  deps: AuditDeps
): Promise<number> {
  // Early validation
  if (options.fix === true && options.json === true && options.yes !== true) {
    throw new Error("--fix --json requires --yes");
  }
  if (options.minTrust !== undefined && options.fix !== true) {
    throw new Error("--min-trust requires --fix");
  }

  const { getInstalledServers, getServer, scanTier1, checkScannerAvailable, scanTier2, computeTrustScore, output } = deps;

  const servers = await getInstalledServers();

  if (servers.length === 0) {
    output("No servers installed. Install one first: mcpm install <name>");
    return 0;
  }

  const spinner = ora({ text: "Auditing installed servers...", isSilent: !process.stdout.isTTY }).start();

  // Check Tier 2 scanner availability once
  const hasExternalScanner = await checkScannerAvailable();

  const results: AuditResult[] = [];

  for (const installedServer of servers) {
    let entry: ServerEntry;
    try {
      entry = await getServer(installedServer.name);
    } catch {
      results.push({
        name: installedServer.name,
        installedServer,
        score: { score: 0, maxPossible: 80, level: "risky", breakdown: { healthCheck: 0, staticScan: 0, externalScan: 0, registryMeta: 0 } },
        findings: [],
        error: "Registry unavailable — could not fetch metadata",
      });
      continue;
    }

    // Run Tier 1 scan
    const tier1Findings = scanTier1(entry);

    // Run Tier 2 scan if available
    const tier2Findings = hasExternalScanner ? await scanTier2(installedServer.name) : [];

    const allFindings = [...tier1Findings, ...tier2Findings];

    const trustScore = computeTrustScore({
      findings: allFindings,
      healthCheckPassed: null,
      hasExternalScanner,
      registryMeta: {
        ...extractRegistryMeta(entry),
        downloadCount: undefined,
      },
    });

    results.push({ name: installedServer.name, installedServer, score: trustScore, findings: allFindings });
  }

  spinner.stop();

  // --json mode (without --fix: bare array; with --fix: wrapped object)
  if (options.json === true) {
    const serversJson = results.map((r) => ({
      name: r.name,
      score: r.score.score,
      maxPossible: r.score.maxPossible,
      level: r.score.level,
      findings: r.findings,
      error: r.error ?? null,
    }));

    if (options.fix === true) {
      // --yes is already guaranteed by the early validation above.
      // Suppress intermediate text output in JSON mode — emit only the final JSON blob.
      const fixOutcome = await runFix(results, options, { ...deps, output: () => undefined });
      output(
        JSON.stringify(
          { servers: serversJson, fix: fixOutcome },
          null,
          2
        )
      );
      const remainingRisky = results
        .filter((r) => !fixOutcome.removed.includes(r.name))
        .some((r) => r.score.level === "risky");
      return remainingRisky || fixOutcome.failed.length > 0 ? 1 : 0;
    }

    output(JSON.stringify(serversJson, null, 2));
    return results.some((r) => r.score.level === "risky") ? 1 : 0;
  }

  // Build table
  const table = new Table({
    head: [
      chalk.cyan("Server"),
      chalk.cyan("Score"),
      chalk.cyan("Level"),
      chalk.cyan("Findings"),
    ],
    style: { head: [], border: [] },
    wordWrap: true,
    colWidths: [45, 25, 12, 10],
  });

  for (const result of results) {
    if (result.error) {
      table.push([
        chalk.white(result.name),
        chalk.gray("N/A"),
        chalk.gray("unknown"),
        chalk.gray("—"),
      ]);
    } else {
      table.push([
        chalk.white(result.name),
        `${scoreBar(result.score.score, result.score.maxPossible, 10)} ${result.score.score}/${result.score.maxPossible}`,
        levelColor(result.score.level),
        String(result.findings.length),
      ]);
    }
  }

  output(table.toString());

  // Summary line
  const safe = results.filter((r) => r.score.level === "safe").length;
  const caution = results.filter((r) => r.score.level === "caution").length;
  const risky = results.filter((r) => r.score.level === "risky").length;
  const registryErrors = results.filter((r) => r.error !== undefined).length;

  const summaryParts = [
    `${results.length} server${results.length !== 1 ? "s" : ""} scanned`,
    `${safe} safe`,
    `${caution} caution`,
    `${risky} risky`,
  ];
  if (registryErrors > 0) {
    summaryParts.push(`${registryErrors} registry error${registryErrors !== 1 ? "s" : ""}`);
  }

  const hasRisky = risky > 0;
  const summaryLine = summaryParts.join(", ");
  output(hasRisky ? chalk.red(summaryLine) : chalk.green(summaryLine));

  // --fix step (non-JSON mode)
  if (options.fix === true) {
    const fixOutcome = await runFix(results, options, deps);
    const remainingRisky = results
      .filter((r) => !fixOutcome.removed.includes(r.name))
      .some((r) => r.score.level === "risky");
    return remainingRisky || fixOutcome.failed.length > 0 ? 1 : 0;
  }

  return hasRisky ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerAuditCommand(program: Command): void {
  program
    .command("audit")
    .description("Scan all installed servers and produce a trust report")
    .option("--json", "Output raw JSON instead of a formatted table")
    .option("--fix", "remove servers whose trust score is below the threshold")
    .option("--min-trust <n>", "threshold used by --fix (default 50)", parseMinTrust)
    .option("-y, --yes", "skip confirmation prompts")
    .action(async (opts: { json?: boolean; fix?: boolean; minTrust?: number; yes?: boolean }) => {
      const { getInstalledServers } = await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { checkScannerAvailable, scanTier2 } = await import("../scanner/tier2.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { getAdapter } = await import("../config/index.js");
      const { getConfigPath } = await import("../config/paths.js");
      const { removeInstalledServer } = await import("../store/servers.js");
      const { createConfirm } = await import("../utils/confirm.js");

      const client = new RegistryClient();

      const deps: AuditDeps = {
        getInstalledServers,
        getServer: (name) => client.getServer(name),
        scanTier1,
        checkScannerAvailable,
        scanTier2,
        computeTrustScore,
        output: stdoutOutput,
        getAdapter,
        getConfigPath,
        removeFromStore: removeInstalledServer,
        confirm: createConfirm(),
      };

      const exitCode = await handleAudit(
        { json: opts.json, fix: opts.fix, minTrust: opts.minTrust, yes: opts.yes },
        deps
      ).catch((err: Error) => {
        console.error(chalk.red(err.message));
        return 1;
      });

      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });
}
