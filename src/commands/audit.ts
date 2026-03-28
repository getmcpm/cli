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
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import ora from "ora";
import type { InstalledServer } from "../store/servers.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditOptions {
  json?: boolean;
}

export interface AuditDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  getServer: (name: string) => Promise<ServerEntry>;
  scanTier1: (entry: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  output: (text: string) => void;
}

interface AuditResult {
  name: string;
  score: TrustScore;
  findings: Finding[];
  error?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function levelColor(level: TrustScore["level"]): string {
  if (level === "safe") return chalk.green(level);
  if (level === "caution") return chalk.yellow(level);
  return chalk.red(level);
}

function scoreBar(score: number, maxPossible: number): string {
  const ratio = score / maxPossible;
  const filled = Math.round(ratio * 10);
  const bar = "█".repeat(filled) + "░".repeat(10 - filled);
  const color = ratio >= 0.8 ? chalk.green : ratio >= 0.5 ? chalk.yellow : chalk.red;
  return `${color(bar)} ${score}/${maxPossible}`;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core logic for `mcpm audit`.
 * Returns exit code: 0 if all safe/caution, 1 if any risky.
 */
export async function handleAudit(
  options: AuditOptions,
  deps: AuditDeps
): Promise<number> {
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

    const official = entry._meta?.["io.modelcontextprotocol.registry/official"] ?? {};
    const trustScore = computeTrustScore({
      findings: allFindings,
      healthCheckPassed: null,
      hasExternalScanner,
      registryMeta: {
        isVerifiedPublisher: official?.status === "active",
        publishedAt: official?.publishedAt,
        downloadCount: undefined,
      },
    });

    results.push({ name: installedServer.name, score: trustScore, findings: allFindings });
  }

  spinner.stop();

  // --json mode
  if (options.json === true) {
    const jsonData = results.map((r) => ({
      name: r.name,
      score: r.score.score,
      maxPossible: r.score.maxPossible,
      level: r.score.level,
      findings: r.findings,
      error: r.error ?? null,
    }));
    output(JSON.stringify(jsonData, null, 2));
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
        scoreBar(result.score.score, result.score.maxPossible),
        levelColor(result.score.level),
        String(result.findings.length),
      ]);
    }
  }

  output(table.toString());

  // Summary line
  const scanned = results.filter((r) => !r.error).length;
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
    .action(async (opts: { json?: boolean }) => {
      const { getInstalledServers } = await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { checkScannerAvailable, scanTier2 } = await import("../scanner/tier2.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");

      const client = new RegistryClient();

      const deps: AuditDeps = {
        getInstalledServers,
        getServer: (name) => client.getServer(name),
        scanTier1,
        checkScannerAvailable,
        scanTier2,
        computeTrustScore,
        output: (text) => process.stdout.write(text + "\n"),
      };

      const exitCode = await handleAudit({ json: opts.json }, deps).catch((err: Error) => {
        console.error(chalk.red(err.message));
        return 1;
      });

      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });
}
