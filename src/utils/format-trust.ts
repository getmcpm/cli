/**
 * Shared trust-score formatting helpers and registry meta extraction.
 * Used across install, audit, update, search, and info commands.
 */

import chalk from "chalk";
import type { ServerEntry } from "../registry/types.js";
import type { TrustScore, TrustScoreInput } from "../scanner/trust-score.js";
import { isCleanPendingHealthCheck } from "../scanner/trust-score.js";

export const OFFICIAL_META_KEY =
  "io.modelcontextprotocol.registry/official" as const;

/**
 * Extract the registryMeta fields from a ServerEntry's _meta block.
 */
export function extractRegistryMeta(
  entry: ServerEntry
): TrustScoreInput["registryMeta"] {
  const official = entry._meta?.[OFFICIAL_META_KEY] ?? {};
  return {
    isVerifiedPublisher: official?.status === "active",
    publishedAt: official?.publishedAt,
  };
}

/**
 * Shown instead of `caution` when the server cleared everything mcpm actually measured
 * and the only unmeasured bucket is the health check. See `isCleanPendingHealthCheck`.
 */
export const CLEAN_PENDING_LABEL = "clean · not run";

/**
 * The verdict to DISPLAY for a score. Not the same as `trust.level`, which stays exactly
 * as computed because it is in the lockfile enum and decides audit's exit code.
 */
export function levelLabel(trust: TrustScore): string {
  return isCleanPendingHealthCheck(trust) ? CLEAN_PENDING_LABEL : trust.level;
}

/**
 * Colorise a trust level string (safe → green, caution → yellow, risky → red).
 *
 * `clean · not run` is cyan, deliberately NOT the green of `safe`: it means "nothing was
 * found", which is a weaker statement than "this was verified", and the two must not read
 * as the same verdict at a glance.
 */
export function levelColor(level: string): string {
  // Matched case-INSENSITIVELY, and the caller's own casing is what gets returned.
  // `install`'s formatTrustScore passes `level.toUpperCase()`, which fell straight through
  // to `default` and printed uncoloured — every trust level in the install flow has been
  // monochrome. Uppercasing the RESULT instead is not an option: it would corrupt the
  // escape sequence chalk wraps the string in.
  switch (level.toLowerCase()) {
    case CLEAN_PENDING_LABEL:
      return chalk.cyan(level);
    case "safe":
      return chalk.green(level);
    case "caution":
      return chalk.yellow(level);
    case "risky":
      return chalk.red(level);
    default:
      return level;
  }
}

/**
 * Render a filled/empty progress bar coloured by ratio.
 *
 * @param score       - The raw score value.
 * @param maxPossible - The maximum possible score.
 * @param length      - Bar character width (default 20).
 */
export function scoreBar(
  score: number,
  maxPossible: number,
  length = 20
): string {
  const ratio = maxPossible > 0 ? score / maxPossible : 0;
  const filled = Math.round(ratio * length);
  const empty = length - filled;
  const bar = "\u2588".repeat(filled) + "\u2591".repeat(empty);
  const colorFn =
    ratio >= 0.8 ? chalk.green : ratio >= 0.5 ? chalk.yellow : chalk.red;
  return colorFn(bar);
}
