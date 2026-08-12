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
import { computeTrustScore as computeTrustScoreReal, externalCredited } from "../scanner/trust-score.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
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
 * An invocation `mcpm audit` cannot satisfy — as opposed to a scan that ran and found
 * something. Both used to leave the process on exit 1, which is audit's documented
 * "a server is risky" CI signal, so a script could not tell "your flag is impossible"
 * from "your servers are bad". These exit 2 instead.
 *
 * A marker class, deliberately: no code enum, no structured payload. The exit code is
 * the whole contract, and CONTRACTS.md permits ADDING codes but never repurposing one.
 */
export class AuditUsageError extends Error {}

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
 *
 * The metadata here is deliberately the most FAVOURABLE a server could present, which
 * makes this a property of the CALL SITE (what audit can measure) rather than of any
 * one server. Folding each server's own `publishedAt` / registry status in instead
 * would lower the ceiling for exactly the servers most worth removing — a publisher
 * could republish to become unremovable, inverting F4's release-age cooldown.
 *
 * Two known residuals, both narrower than the band this guard closes, both stated in
 * the CHANGELOG rather than papered over:
 *  - 62 is reachable only by a pypi/oci server. Every npm package draws one `low`
 *    `install-script` finding for the `npx -y` launcher class, so a clean npm server
 *    tops out at 60 — leaving `--min-trust 61..62` as a threshold an all-npm stack
 *    cannot satisfy. Pinned by a test against the real scorer.
 *  - A server that is not a verified publisher, or was published within 30 days,
 *    tops out lower still (59 / 58). That is the registryMeta bucket doing its job —
 *    evidence, not a measurement gap — so it is not laundered into an exemption.
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
 * A server banked the bucket iff the scorer WIDENED its denominator — `externalCredited`
 * asks the scorer's own record of that decision, so the ceiling and the credited-ness
 * test cannot drift apart.
 *
 * `Math.min` is the reducer, and the earlier `Math.max` was the bug. Crediting is
 * decided PER SERVER (a `scanner-error` is emitted per invocation), so a half-working
 * scanner yields a MIXED run — and `Math.max` let one credited server license a
 * threshold in 63..82 that no uncredited server could reach, whereupon the raw
 * candidate filter deleted those uncredited servers even though their evidence was
 * flawless. "The servers below it are below it on evidence" was false for exactly
 * them: `computeTrustScore` treats a scanner-error as the scanner being ABSENT, which
 * is a statement about the user's scanner, not about the server.
 *
 * So the claim this guard enforces is the strong one — no server in this run could
 * clear this threshold — and a run where any server structurally cannot is refused
 * whole. Refusing deletes nothing, which is the only safe direction on the CLI's one
 * destructive score gate; the alternative (silently sparing the servers that cannot
 * reach the bar, and removing the rest) would spare whichever server most recently
 * broke the user's scanner.
 */
function minAchievableAuditScore(scored: readonly TrustScore[]): number {
  const credited = flawlessAuditScore(true);
  const native = flawlessAuditScore(false);
  return Math.min(...scored.map((t) => (externalCredited(t) ? credited.score : native.score)));
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
    throw new AuditUsageError("--fix --json requires --yes");
  }
  if (options.minTrust !== undefined && options.fix !== true) {
    throw new AuditUsageError("--min-trust requires --fix");
  }
  // The SARIF branch returns before the fix step, so `--sarif --fix` never removed
  // anything — the flag was accepted and silently dropped. Rejecting the combination
  // fixes that, and incidentally keeps the `--min-trust` ceiling guard from refusing a
  // report-only run that could not have deleted anything either.
  if (options.sarif === true && options.fix === true) {
    throw new AuditUsageError(
      "--sarif is report-only and cannot be combined with --fix. Run them as separate commands."
    );
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
  // CREDIT. See `minAchievableAuditScore`.
  //
  // Refuse rather than warn, and refuse the whole run. Under the `Math.min` reducer the
  // condition is "at least one scanned server cannot reach this threshold whatever its
  // evidence" — so a refusal can land on a run where some OTHER server was genuinely
  // removable. That is the deliberate trade: the alternative is deleting the servers
  // that cannot reach the bar, and on the CLI's one destructive score gate a false
  // refusal costs a re-run while a false deletion costs the user their config and the
  // plaintext credentials in it.
  if (options.fix === true && options.minTrust !== undefined) {
    // Servers whose registry lookup failed are never removal candidates, so they must
    // not drag the ceiling down. If none scanned, there is nothing to remove either —
    // and `Math.min(...[])` is +Infinity, which would silently disable the guard.
    const scanned = results.filter((r) => r.error === undefined).map((r) => r.score);
    if (scanned.length > 0) {
      const ceiling = minAchievableAuditScore(scanned);
      if (options.minTrust > ceiling) {
        // Name the servers that hold the ceiling down in a mixed-credit run. Without
        // this the message reads as a flat property of the command, and the user has
        // no way to see that their scanner failed on some servers and not others.
        const uncredited = results
          .filter((r) => r.error === undefined && !externalCredited(r.score))
          .map((r) => r.name);
        const mixed = uncredited.length > 0 && uncredited.length < scanned.length;
        // Advise the highest score a server in THIS run actually reached, never the
        // model ceiling. The ceiling is what a hypothetical best server could score, and
        // recommending it walks the user straight into the residual band: a clean npm
        // server tops out at 60 (the `npx -y` launcher class costs one `low`), so
        // "use --min-trust 62" would remove an entire all-npm stack — the outcome this
        // guard exists to prevent. The best observed score is the largest threshold that
        // is not vacuous: at least one server is at or above it by construction.
        const bestObserved = Math.max(...scanned.map((t) => t.score));
        throw new AuditUsageError(
          `--min-trust ${options.minTrust} is above ${ceiling}, the highest score \`mcpm audit\` ` +
            `could produce for every one of these servers. ` +
            `At least one would fall below it whatever its evidence, so --fix would propose it for removal. ` +
            (mixed
              ? `The external scanner was not credited for ${uncredited.length} of ${scanned.length} servers ` +
                // Not `.map(sanitizeForTerminal)`: its second parameter is a length
                // cap, and map would pass the array index into it — truncating the
                // first name to zero characters.
                `(${uncredited.map((n) => sanitizeForTerminal(n)).join(", ")}), which caps them at ${ceiling}. ` +
                `A scanner that answers \`--version\` but cannot scan a server still counts as absent. `
              : "") +
            `Audit does not execute servers, so the health check never runs (15 of 30 points), and it does not ` +
            `read download counts (registry metadata caps at 7 of 10). ` +
            `The highest score any server here actually reached is ${bestObserved} — use --min-trust ${bestObserved} or lower, ` +
            `since a higher threshold removes servers for what audit cannot measure rather than for their evidence.`
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
        // Exit 2 marks "this invocation cannot be satisfied", keeping audit's
        // documented exit 1 ("a server is risky") meaningful to CI. Commander's own
        // argument-parse failures (e.g. `--min-trust 150`) still exit 1 — they never
        // reach this handler.
        return err instanceof AuditUsageError ? 2 : 1;
      });

      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });
}
