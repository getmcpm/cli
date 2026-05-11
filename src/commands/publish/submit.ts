/**
 * `mcpm publish` — submit to the official MCP registry.
 * Token is read from GITHUB_TOKEN or MCPM_TOKEN env only (never from CLI flags).
 */

import chalk from "chalk";
import { RegistryError } from "../../registry/errors.js";
import type { PublishManifest } from "./manifest.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { TrustScore, TrustScoreInput } from "../../scanner/trust-score.js";
import { PublishErrors } from "../../errors/publish-errors.js";
import { manifestToEntry, assertTrustGate } from "./check.js";

export interface SubmitResult {
  url: string;
}

export interface PublishSubmitDeps {
  readManifest: () => Promise<PublishManifest | null>;
  scanTier1: (entry: ServerEntry) => Finding[];
  computeTrustScore: (input: TrustScoreInput) => TrustScore;
  submitToRegistry: (manifest: PublishManifest, token: string, registryUrl: string) => Promise<SubmitResult>;
  getToken: () => string | null;
  output: (text: string) => void;
}

export interface PublishSubmitOptions {
  registryUrl?: string;
}

const DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io";

export async function handlePublishSubmit(
  options: PublishSubmitOptions,
  deps: PublishSubmitDeps
): Promise<void> {
  const { readManifest, scanTier1, submitToRegistry, getToken, output } = deps;
  const registryUrl = options.registryUrl ?? DEFAULT_REGISTRY;

  const manifest = await readManifest();
  if (!manifest) throw PublishErrors.manifestNotFound();

  const token = getToken();
  if (!token) throw PublishErrors.tokenRequired();

  assertTrustGate(scanTier1(manifestToEntry(manifest)));

  try {
    const result = await submitToRegistry(manifest, token, registryUrl);
    output(chalk.green(`\nPublished successfully!`));
    output(`  Registry URL: ${chalk.cyan(result.url)}`);
  } catch (err) {
    // 404 or 405: registry publish endpoint not yet live
    if (err instanceof RegistryError && (err.statusCode === 404 || err.statusCode === 405)) {
      output(PublishErrors.registryApiUnavailable().message);
      return;
    }
    throw err;
  }
}

/** Read GitHub token from environment only. Never from CLI flags. */
export function getTokenFromEnv(): string | null {
  return process.env.GITHUB_TOKEN ?? process.env.MCPM_TOKEN ?? null;
}
