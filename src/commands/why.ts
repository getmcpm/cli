/**
 * `mcpm why <server>` — explain a server's trust score.
 *
 * Renders the same trust assessment `mcpm install` runs, but as an auditable
 * breakdown: each component's earned/max points, every finding (severity +
 * message + location), whether registry metadata was zeroed by critical/high
 * findings, and the declared environment variables. Read-only; no install.
 *
 * Exports:
 * - handleWhy()        — injectable handler for testing
 * - registerWhyCommand() — Commander registration
 */

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import type { RegistryClient } from "../registry/client.js";
import type { ServerEntry, EnvVar } from "../registry/types.js";
import type { Finding } from "../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { NotFoundError } from "../registry/errors.js";
import { assessReleaseAge } from "../scanner/cooldown.js";
import { scoreBar, levelColor, extractRegistryMeta } from "../utils/format-trust.js";
import { stdoutOutput } from "../utils/output.js";
import { valid as semverValid } from "semver";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import type { NpmProvenanceSnapshot } from "../registry/npm-provenance.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WhyOptions {
  json?: boolean;
}

export interface WhyDeps {
  registryClient: Pick<RegistryClient, "getServer">;
  scanTier1: (entry: ServerEntry) => Finding[];
  checkScannerAvailable: () => Promise<boolean>;
  scanTier2: (name: string) => Promise<Finding[]>;
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  output: (text: string) => void;
  /** Epoch-ms clock for release-age assessment; defaults to Date.now at the CLI boundary. */
  now?: () => number;
  /**
   * F8: fetch npm's parse-only provenance record for the npm coordinate.
   * Optional — the Provenance section is skipped when absent. FAIL-OPEN.
   */
  fetchNpmProvenance?: (
    identifier: string,
    npmVersion: string
  ) => Promise<NpmProvenanceSnapshot | undefined>;
}

// ---------------------------------------------------------------------------
// Helpers — pure
// ---------------------------------------------------------------------------

const SEVERITY_COLOR: Record<Finding["severity"], (s: string) => string> = {
  critical: chalk.red,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.dim,
};

function hasCriticalOrHigh(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === "critical" || f.severity === "high");
}

/** The package whose env vars install would use: npm → pypi → oci → first. */
function bestPackage(entry: ServerEntry): ServerEntry["server"]["packages"][number] | undefined {
  const { packages } = entry.server;
  return (
    packages.find((p) => p.registryType === "npm") ??
    packages.find((p) => p.registryType === "pypi") ??
    packages.find((p) => p.registryType === "oci") ??
    packages[0]
  );
}

function componentLine(label: string, earned: number, max: number, note?: string): string {
  const ratio = max > 0 ? earned / max : 0;
  const color = ratio >= 0.8 ? chalk.green : ratio >= 0.5 ? chalk.yellow : chalk.red;
  const score = color(`${earned}/${max}`.padStart(6));
  const suffix = note ? chalk.dim(`  ${note}`) : "";
  return `  ${label.padEnd(16)}${score}${suffix}`;
}

/**
 * Render the F8 Provenance section. HONESTY: "attested" is an UNVERIFIED registry
 * record (build identity, NOT safety) — never "verified". Identity strings are
 * unverified registry free text, so sanitizeForTerminal them before display. An
 * undefined snapshot (non-npm, non-concrete version, or fetch fail-open) yields
 * no section.
 */
function provenanceLines(snap: NpmProvenanceSnapshot | undefined): string[] {
  if (snap === undefined) return [];
  const lines = ["", chalk.cyan("Provenance:")];
  if (snap.status === "attested") {
    const id = snap.identity;
    lines.push(`  ${chalk.green("attested")} ${chalk.dim("(unverified registry record — build identity, not safety)")}`);
    if (id?.sourceRepo) lines.push(`  ${"source".padEnd(10)}${sanitizeForTerminal(id.sourceRepo)}`);
    if (id?.workflowPath) {
      const ref = id.workflowRef ? ` @ ${sanitizeForTerminal(id.workflowRef)}` : "";
      lines.push(`  ${"workflow".padEnd(10)}${sanitizeForTerminal(id.workflowPath)}${ref}`);
    }
    if (id?.commitSha) lines.push(`  ${"commit".padEnd(10)}${sanitizeForTerminal(id.commitSha)}`);
  } else if (snap.status === "unsigned") {
    lines.push(`  ${chalk.dim("unsigned")} ${chalk.dim("(no published attestation — neutral, no penalty)")}`);
  } else {
    lines.push(`  ${chalk.dim("unsupported")} ${chalk.dim("(attestation present but not a recognized shape)")}`);
  }
  return lines;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function handleWhy(
  name: string,
  options: WhyOptions,
  deps: WhyDeps
): Promise<void> {
  const { registryClient, scanTier1, checkScannerAvailable, scanTier2, computeTrustScore, output } = deps;

  const spinner = ora({ text: "Assessing...", isSilent: !process.stdout.isTTY }).start();

  let entry: ServerEntry;
  try {
    entry = await registryClient.getServer(name);
  } catch (err) {
    spinner.stop();
    if (err instanceof NotFoundError) {
      output(`Server '${name}' not found`);
      return;
    }
    throw err;
  }

  const tier1 = scanTier1(entry);
  const scannerAvailable = await checkScannerAvailable();
  const registryMeta = extractRegistryMeta(entry);
  // Default 24h threshold — why has no policy context; the medium finding is
  // the unconditional soft penalty, rendered by the generic finding loop.
  const releaseAge = assessReleaseAge({
    publishedAt: registryMeta.publishedAt,
    now: (deps.now ?? Date.now)(),
  });
  const findings: Finding[] = [
    ...tier1,
    ...(scannerAvailable ? await scanTier2(name) : []),
    ...(releaseAge.finding ? [releaseAge.finding] : []),
  ];

  // F8: parse-only provenance for a concrete npm coordinate (fail-open; no
  // section for non-npm, non-concrete versions, or a failed fetch). Fetched
  // while the spinner is still up.
  const pkg = bestPackage(entry);
  let provenance: NpmProvenanceSnapshot | undefined;
  if (deps.fetchNpmProvenance && pkg?.registryType === "npm" && semverValid(pkg.version ?? null) !== null) {
    provenance = await deps.fetchNpmProvenance(pkg.identifier, pkg.version as string);
  }

  spinner.stop();

  const trust = computeTrustScore({
    findings,
    healthCheckPassed: null, // health check only runs at install
    hasExternalScanner: scannerAvailable,
    registryMeta,
  });

  const metaCapped = hasCriticalOrHigh(findings);
  const envVars: EnvVar[] = pkg?.environmentVariables ?? [];

  if (options.json === true) {
    output(
      JSON.stringify(
        {
          name: entry.server.name,
          version: entry.server.version,
          score: trust.score,
          maxPossible: trust.maxPossible,
          level: trust.level,
          breakdown: trust.breakdown,
          externalScannerAvailable: scannerAvailable,
          registryMetaCapped: metaCapped,
          provenance: provenance ?? null,
          findings,
          environmentVariables: envVars.map((ev) => ({
            name: ev.name,
            required: ev.isRequired === true,
            secret: ev.isSecret === true,
          })),
        },
        null,
        2
      )
    );
    return;
  }

  const { score, maxPossible, level, breakdown } = trust;
  const lines: string[] = [];

  lines.push(`${chalk.bold.white(entry.server.name)}  ${chalk.dim(`v${entry.server.version}`)}`);
  lines.push("");
  lines.push(`${scoreBar(score, maxPossible)}  ${score}/${maxPossible}  (${levelColor(level)})`);
  lines.push("");
  lines.push(componentLine("Health check", breakdown.healthCheck, 30, "not run until install"));
  lines.push(componentLine("Static scan", breakdown.staticScan, 40));
  lines.push(
    componentLine(
      "External scan",
      breakdown.externalScan,
      20,
      scannerAvailable ? undefined : "install mcp-scan for deeper analysis"
    )
  );
  lines.push(
    componentLine("Registry meta", breakdown.registryMeta, 10, metaCapped ? "capped: critical/high findings" : undefined)
  );

  lines.push("");
  if (findings.length === 0) {
    lines.push(chalk.green("Findings: none"));
  } else {
    lines.push(chalk.cyan(`Findings (${findings.length}):`));
    for (const f of findings) {
      const sev = SEVERITY_COLOR[f.severity](`[${f.severity}]`);
      lines.push(`  ${sev} ${chalk.dim(f.type)} — ${f.message} ${chalk.dim(`(${f.location})`)}`);
    }
  }

  lines.push(...provenanceLines(provenance));

  if (envVars.length > 0) {
    lines.push("");
    lines.push(chalk.cyan("Environment variables:"));
    for (const ev of envVars) {
      const tags = [
        ev.isRequired === true ? chalk.red("required") : chalk.dim("optional"),
        ...(ev.isSecret === true ? [chalk.yellow("secret")] : []),
      ].join(" ");
      lines.push(`  ${chalk.white(ev.name)}  [${tags}]`);
    }
  }

  output(lines.join("\n"));
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

export function registerWhyCommand(program: Command): void {
  program
    .command("why <name>")
    .description("Explain a server's trust score (auditable breakdown of findings + components)")
    .option("--json", "output the breakdown as JSON")
    .action(async (name: string, opts: { json?: boolean }) => {
      const { RegistryClient } = await import("../registry/client.js");
      const { scanTier1 } = await import("../scanner/tier1.js");
      const { checkScannerAvailable, scanTier2 } = await import("../scanner/tier2.js");
      const { computeTrustScore } = await import("../scanner/trust-score.js");
      const { fetchNpmProvenance } = await import("../registry/npm-provenance.js");

      try {
        await handleWhy(
          name,
          { json: opts.json },
          {
            registryClient: new RegistryClient(),
            scanTier1,
            checkScannerAvailable,
            scanTier2: (serverName: string) => scanTier2(serverName),
            computeTrustScore,
            output: stdoutOutput,
            now: () => Date.now(),
            fetchNpmProvenance,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
