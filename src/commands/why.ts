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
import { scoreBar, levelColor, extractRegistryMeta } from "../utils/format-trust.js";
import { stdoutOutput } from "../utils/output.js";

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
  const findings: Finding[] = scannerAvailable
    ? [...tier1, ...(await scanTier2(name))]
    : [...tier1];

  spinner.stop();

  const trust = computeTrustScore({
    findings,
    healthCheckPassed: null, // health check only runs at install
    hasExternalScanner: scannerAvailable,
    registryMeta: extractRegistryMeta(entry),
  });

  const metaCapped = hasCriticalOrHigh(findings);
  const envVars: EnvVar[] = bestPackage(entry)?.environmentVariables ?? [];

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
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
