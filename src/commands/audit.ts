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
import { buildSarif } from "../output/sarif.js";
import { computeTrustScore as computeTrustScoreReal } from "../scanner/trust-score.js";
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

/**
 * A flawless server — zero findings, active registry status, years-old publish date —
 * scored exactly the way `mcpm audit` scores real ones.
 *
 * Audit deliberately does not execute installed servers, so the health check never
 * runs (`healthCheckPassed: null` => 15 of 30), and it does not read download counts
 * (registry metadata caps at 7 of 10). 18 of the 80 mcpm-native points are therefore
 * unreachable HERE: the best possible server tops out at 62, or 82 once the external
 * bucket is credited.
 *
 * Uses the REAL scorer, not `deps.computeTrustScore`, and that is deliberate: this is
 * a property of the scoring MODEL, not of whatever a caller injected. Deriving it from
 * the injected scorer is not merely untestable but wrong — the suite's mock returns
 * one constant for every input, which collapses the ceiling onto each server's own
 * score and fires the guard exactly when a server is legitimately below the threshold.
 */
function flawlessAuditScore(hasExternalScanner: boolean): TrustScore {
  return computeTrustScoreReal({
    findings: [],
    healthCheckPassed: null,
    hasExternalScanner,
    registryMeta: {
      isVerifiedPublisher: true,
      publishedAt: "1970-01-01T00:00:00.000Z",
      downloadCount: undefined,
    },
  });
}

/**
 * The best score the servers in THIS run could actually have reached.
 *
 * Keyed on what the run actually CREDITED, never on `checkScannerAvailable()`. Those
 * are different predicates and the gap is exploitable: availability is a bare
 * `<cmd> --version` exit-0 probe, while `computeTrustScore` credits the 20-point
 * bucket only when the scanner also returned output it could READ. A scanner that
 * answers `--version` but cannot scan a registry server name — which is precisely
 * what wiring a real scanner would produce today, see the note in `scanner/tier2.ts` —
 * yields a `scanner-error` finding per server, leaving every server capped at 62 while
 * an availability-keyed ceiling would read 82 and wave through the whole 63–82 band.
 * That band is the mass delete this guard exists to prevent.
 *
 * A server banked the bucket iff the scorer WIDENED its denominator, so both the
 * ceiling and the credited-ness test come from the same function and cannot drift
 * apart. `Math.max` is the right reducer: the guard's claim is "no server in this run
 * could have cleared this threshold", so one server that could have is enough to make
 * the threshold meaningful, and the servers below it are below it on evidence.
 */
function maxAchievableAuditScore(scored: readonly TrustScore[]): number {
  const credited = flawlessAuditScore(true);
  const native = flawlessAuditScore(false);
  return Math.max(
    ...scored.map((t) => (t.maxPossible === credited.maxPossible ? credited.score : native.score))
  );
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AuditOptions {
  json?: boolean;
  sarif?: boolean;
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

  // Build candidates on the RAW score, deliberately — do NOT switch this to
  // `nativeTrustScore`. This is the `audit --fix` sibling of TODOS #35, resolved as
  // covered by the #33 carve-out (see nativeTrustScore's docblock in
  // scanner/trust-score.ts).
  //
  // #33 and #35 native-ised gates that REFUSE, where the caller was an agent or a
  // locked baseline. This is the only score-gated DESTRUCTIVE site in the CLI and it
  // is human-only — the MCP audit tool is read-only and reaches no removal path — so
  // subtracting the external bucket here deletes MORE rather than refusing more.
  // Measured 2026-08-12 over 1,199 live registry entries through the real scanTier1
  // and computeTrustScore with this command's inputs: a native filter changes 0 of
  // 1,199 at the default threshold (the flip band needs >=1 high, >=1 critical or
  // >=3 mediums, and the live registry has none) while deleting every server once
  // the threshold passes the native ceiling of 62. It pays its whole cost above the
  // ceiling and collects nothing below it.
  //
  // The masking it would close is deliberate self-deception, which trust-score.ts
  // already documents as unclosable; a scanner that merely BREAKS is treated as
  // ABSENT upstream by the scanner-error check, not as a clean scan.
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

  // `--min-trust` accepts 0-100, but this command's own scale stops well short of
  // that. A threshold above what any server in this run could reach puts EVERY server
  // below it by construction, so `--fix` would propose the user's entire stack for
  // removal however clean it is — and `--fix --json` forces `--yes` and suppresses the
  // candidate list, so it arrives as a silent mass delete whose config `.bak` is not a
  // pre-removal snapshot (BaseAdapter writes it once per file lifetime). Measured
  // before this guard: a flawless server scores 62, and `--min-trust 63` removed 3 of
  // 3 such servers.
  //
  // Runs AFTER the scan and BEFORE every output branch: nothing has been deleted yet
  // (`runFix` is further down), and only here is it known what the run actually
  // credited — which is the whole point, since scanner AVAILABILITY is not scanner
  // CREDIT. See `maxAchievableAuditScore`.
  //
  // Refuse rather than warn. This is arithmetic, not a heuristic — there is no
  // false-positive to trade against, because "threshold above the maximum" and "every
  // server is below the threshold" are the same statement.
  if (options.fix === true && options.minTrust !== undefined) {
    // Servers whose registry lookup failed are never removal candidates, so they must
    // not drag the ceiling down. If none scanned, there is nothing to remove either.
    const scanned = results.filter((r) => r.error === undefined).map((r) => r.score);
    if (scanned.length > 0) {
      const ceiling = maxAchievableAuditScore(scanned);
      if (options.minTrust > ceiling) {
        const credited = scanned.some((t) => t.maxPossible === flawlessAuditScore(true).maxPossible);
        throw new Error(
          `--min-trust ${options.minTrust} is above ${ceiling}, the highest score \`mcpm audit\` ` +
            `could produce for any of these servers` +
            `${credited ? " (with your external scanner credited)" : ""}. ` +
            `Every installed server would fall below it, so --fix would propose your whole stack for removal. ` +
            `Audit does not execute servers, so the health check never runs (15 of 30 points), and it does not ` +
            `read download counts (registry metadata caps at 7 of 10). Use --min-trust ${ceiling} or lower.`
        );
      }
    }
  }

  // --sarif mode: a read-only SARIF 2.1.0 report for GitHub code-scanning. Report
  // only — never fixes. Exit code matches audit's contract (risky → 1); upload with
  // `if: always()` so the artifact survives a non-zero audit.
  if (options.sarif === true) {
    // __PKG_VERSION__ is a tsup build-time define; guard for non-bundled (test) runs.
    const version = typeof __PKG_VERSION__ === "string" ? __PKG_VERSION__ : "0.0.0";
    output(
      JSON.stringify(
        buildSarif(
          results.map((r) => ({ name: r.name, findings: r.findings })),
          version
        ),
        null,
        2
      )
    );
    return results.some((r) => r.score.level === "risky") ? 1 : 0;
  }

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
    .option("--sarif", "Output a SARIF 2.1.0 report for GitHub code-scanning (report only)")
    .option("--fix", "remove servers whose trust score is below the threshold")
    .option("--min-trust <n>", "threshold used by --fix (default 50)", parseMinTrust)
    .option("-y, --yes", "skip confirmation prompts")
    .action(async (opts: { json?: boolean; sarif?: boolean; fix?: boolean; minTrust?: number; yes?: boolean }) => {
      const { getInstalledServers } = await import("../store/servers.js");
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { checkScannerAvailable, scanTier2 } = await import("../scanner/tier2.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { getAdapter } = await import("../config/index.js");
      const { getConfigPath } = await import("../config/paths.js");
      const { removeInstalledServer } = await import("../store/servers.js");
      const { confirm } = await import("../utils/confirm.js");

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
        confirm,
      };

      const exitCode = await handleAudit(
        { json: opts.json, sarif: opts.sarif, fix: opts.fix, minTrust: opts.minTrust, yes: opts.yes },
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
