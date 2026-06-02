/**
 * `mcpm publish check` — dry-run publish: show trust score and what would be submitted.
 */

import chalk from "chalk";
import type { PublishManifest } from "./manifest.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../../scanner/trust-score.js";
import { PublishErrors } from "../../errors/publish-errors.js";
import { levelColor } from "../../utils/format-trust.js";

const PLACEHOLDER_VERSION = "0.0.0";

export interface PublishCheckDeps {
  readManifest: () => Promise<PublishManifest | null>;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  output: (text: string) => void;
}

export interface PublishCheckOptions {
  registryUrl?: string;
}

export function manifestToEntry(manifest: PublishManifest): ServerEntry {
  return {
    server: {
      name: manifest.name,
      description: manifest.description,
      version: PLACEHOLDER_VERSION,
      repository: manifest.homepage ? { url: manifest.homepage } : undefined,
      packages: [
        {
          registryType: manifest.package.registryType,
          identifier: manifest.package.identifier,
          version: PLACEHOLDER_VERSION,
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
      remotes: [],
    },
    _meta: {},
  } as unknown as ServerEntry;
}

/**
 * Number of medium-severity findings that, in aggregate, block publishing.
 * Issue #24: the gate was blind to mediums, so a server with several
 * exfiltration-shaped args could publish cleanly.
 */
const MEDIUM_BLOCK_THRESHOLD = 3;

/**
 * Throws a PublishError when findings should block submission.
 *
 * Blocking conditions (issue #24 — fail safe, don't be blind to mediums):
 * - any critical or high finding, OR
 * - any exfil-args finding (data-exfiltration-shaped argument), OR
 * - MEDIUM_BLOCK_THRESHOLD or more medium findings in aggregate.
 */
export function assertTrustGate(findings: Finding[]): void {
  const criticalOrHigh = findings.filter(
    (f): f is Finding & { severity: "critical" | "high" } =>
      f.severity === "critical" || f.severity === "high"
  );

  const exfilArgs = findings.filter((f) => f.type === "exfil-args");
  const mediums = findings.filter((f) => f.severity === "medium");

  const blockOnMediumCount = mediums.length >= MEDIUM_BLOCK_THRESHOLD;

  if (criticalOrHigh.length === 0 && exfilArgs.length === 0 && !blockOnMediumCount) {
    return;
  }

  // Build a deduplicated blocking list: all critical/high, plus the exfil-arg
  // findings (and, when the medium-count threshold is tripped, the mediums).
  const blocking: Finding[] = [
    ...criticalOrHigh,
    ...exfilArgs.filter((f) => f.severity !== "critical" && f.severity !== "high"),
  ];
  if (blockOnMediumCount) {
    for (const m of mediums) {
      if (!blocking.includes(m)) blocking.push(m);
    }
  }

  throw PublishErrors.trustGateBlocked(blocking);
}

export async function handlePublishCheck(
  _options: PublishCheckOptions,
  deps: PublishCheckDeps
): Promise<void> {
  const { readManifest, scanTier1, computeTrustScore, output } = deps;

  const manifest = await readManifest();
  if (!manifest) throw PublishErrors.manifestNotFound();

  const findings = scanTier1(manifestToEntry(manifest));
  assertTrustGate(findings);

  const score = computeTrustScore({
    findings,
    healthCheckPassed: null,
    hasExternalScanner: false,
    registryMeta: {},
  });

  output(chalk.bold("mcpm publish check"));
  output(`  Package:     ${chalk.white(manifest.name)}`);
  output(`  Type:        ${manifest.package.registryType} (${manifest.package.identifier})`);
  if (manifest.homepage) output(`  Homepage:    ${manifest.homepage}`);
  output(`  Tags:        ${manifest.tags.join(", ") || "(none)"}`);
  output(`  Trust score: ${levelColor(score.level)} (${score.score}/100)`);
  output(chalk.green("\nReady to publish. Run 'mcpm publish' to submit."));
}
