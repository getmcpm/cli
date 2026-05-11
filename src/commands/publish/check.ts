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

/** Throws a PublishError if any critical or high findings are present. */
export function assertTrustGate(findings: Finding[]): void {
  const blocking = findings.filter(
    (f): f is Finding & { severity: "critical" | "high" } =>
      f.severity === "critical" || f.severity === "high"
  );
  if (blocking.length > 0) throw PublishErrors.trustGateBlocked(blocking);
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
