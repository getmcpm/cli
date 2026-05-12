/**
 * `mcpm outdated` — show installed servers with newer registry versions or trust regressions.
 *
 * Shares version-drift logic with `mcpm update` via checkVersionDrift().
 * Always bypasses the cache to return fresh results.
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import semver from "semver";
import type { InstalledServer } from "../store/servers.js";
import type { ServerEntry } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { levelColor, extractRegistryMeta } from "../utils/format-trust.js";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OutdatedOptions {
  json?: boolean;
}

export interface OutdatedDeps {
  getInstalledServers: () => Promise<InstalledServer[]>;
  /** Must always fetch fresh (bypass cache). */
  getServer: (name: string) => Promise<ServerEntry>;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  output: (text: string) => void;
}

export interface DriftRow {
  name: string;
  installedVersion: string;
  latestVersion: string | null;
  installedTrustScore: number | undefined;
  latestTrustScore: number | null;
  latestLevel: "safe" | "caution" | "risky" | null;
  versionChange: "none" | "patch" | "minor" | "major" | "unknown";
  trustRegression: boolean;
  error?: string;
}

// ---------------------------------------------------------------------------
// Shared drift-check logic (reused by `mcpm update`)
// ---------------------------------------------------------------------------

/**
 * Compare installed servers against the registry and return drift rows.
 * Pure function — no I/O side effects beyond the injected deps.
 */
export async function checkVersionDrift(
  installed: InstalledServer[],
  getServer: OutdatedDeps["getServer"],
  scanTier1: OutdatedDeps["scanTier1"],
  computeTrustScore: OutdatedDeps["computeTrustScore"]
): Promise<DriftRow[]> {
  const rows = await Promise.all(
    installed.map(async (s): Promise<DriftRow> => {
      let entry: ServerEntry;
      try {
        entry = await getServer(s.name);
      } catch {
        return {
          name: s.name,
          installedVersion: s.version,
          latestVersion: null,
          installedTrustScore: s.trustScore,
          latestTrustScore: null,
          latestLevel: null,
          versionChange: "unknown",
          trustRegression: false,
          error: "Registry unavailable",
        };
      }

      const latest = entry.server.version;
      // Normalise semver.diff pre* variants to their base type for display
      const rawDiff = semver.valid(s.version) && semver.valid(latest)
        ? (semver.diff(s.version, latest) ?? "none")
        : "unknown";
      const VALID_CHANGES = new Set(["none", "patch", "minor", "major"]);
      const stripped = rawDiff.replace(/^pre/, "");
      const versionChange = (VALID_CHANGES.has(stripped) ? stripped : "unknown") as DriftRow["versionChange"];

      let findings: Finding[] = [];
      let latestScore: TrustScore;
      try {
        findings = scanTier1(entry);
        latestScore = computeTrustScore({
          findings,
          healthCheckPassed: null,
          hasExternalScanner: false,
          registryMeta: { ...extractRegistryMeta(entry), downloadCount: undefined },
        });
      } catch {
        return {
          name: s.name,
          installedVersion: s.version,
          latestVersion: latest,
          installedTrustScore: s.trustScore,
          latestTrustScore: null,
          latestLevel: null,
          versionChange,
          trustRegression: false,
          error: "Trust assessment failed",
        };
      }

      const trustRegression =
        s.trustScore !== undefined &&
        latestScore.score < s.trustScore &&
        s.version === latest;

      return {
        name: s.name,
        installedVersion: s.version,
        latestVersion: latest,
        installedTrustScore: s.trustScore,
        latestTrustScore: latestScore.score,
        latestLevel: latestScore.level,
        versionChange,
        trustRegression,
      };
    })
  );

  return rows;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleOutdated(
  options: OutdatedOptions,
  deps: OutdatedDeps
): Promise<void> {
  const { getInstalledServers, getServer, scanTier1, computeTrustScore, output } = deps;

  const installed = await getInstalledServers();

  if (installed.length === 0) {
    output("No servers installed.");
    return;
  }

  const spinner = ora({ text: "Checking registry…", isSilent: !process.stdout.isTTY }).start();
  const rows = await checkVersionDrift(installed, getServer, scanTier1, computeTrustScore);
  spinner.stop();

  if (options.json) {
    output(JSON.stringify(rows, null, 2));
    return;
  }

  const errors = rows.filter((r) => r.error);
  const outdated = rows.filter((r) => !r.error && (r.versionChange !== "none" || r.trustRegression));

  for (const r of errors) {
    output(chalk.yellow(`  ${r.name}: ${r.error}`));
  }

  if (outdated.length === 0) {
    const clean = rows.filter((r) => !r.error);
    if (clean.length > 0) output(chalk.green("All servers are up to date."));
    return;
  }

  output(chalk.bold("\nOutdated servers:"));
  const colWidth = Math.max(...outdated.map((r) => r.name.length), 10);

  for (const r of outdated) {
    const nameCol = chalk.white(r.name.padEnd(colWidth));
    if (r.trustRegression) {
      const was = r.installedTrustScore ?? "?";
      const now = r.latestTrustScore ?? "?";
      output(`  ${nameCol}  ${chalk.yellow(`trust score regression: ${was} → ${now}`)}`);
    } else {
      const diffColor =
        r.versionChange === "major" ? chalk.red
        : r.versionChange === "minor" ? chalk.yellow
        : chalk.cyan;
      const latest = r.latestVersion ?? "unknown";
      const trustStr = r.latestTrustScore !== null && r.latestLevel
        ? `  [${levelColor(r.latestLevel)}]`
        : "";
      output(`  ${nameCol}  ${chalk.yellow(r.installedVersion)} → ${diffColor(latest)}${trustStr}`);
    }
  }

  const hasVersionUpdates = outdated.some((r) => r.versionChange !== "none");
  if (hasVersionUpdates) {
    output(`\nRun ${chalk.cyan("mcpm update")} to apply updates.`);
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerOutdatedCommand(program: Command): void {
  program
    .command("outdated")
    .description("Show installed servers with available updates or trust regressions")
    .option("--json", "Output raw JSON")
    .action(async (opts: { json?: boolean }) => {
      const { getInstalledServers } = await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");

      const client = new RegistryClient();

      await handleOutdated({ json: opts.json }, {
        getInstalledServers,
        // forceRefresh: RegistryClient has no cache internally — cache lives in commands
        // that wrap it with store/cache.ts. Calling getServer directly bypasses it.
        getServer: (name) => client.getServer(name),
        scanTier1,
        computeTrustScore,
        output: stdoutOutput,
      }).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
