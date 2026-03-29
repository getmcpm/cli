/**
 * Shared trust-score formatting helpers and registry meta extraction.
 * Used across install, audit, update, search, and info commands.
 */

import chalk from "chalk";
import type { ServerEntry } from "../registry/types.js";
import type { TrustScoreInput } from "../scanner/trust-score.js";

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
 * Colorise a trust level string (safe → green, caution → yellow, risky → red).
 */
export function levelColor(level: string): string {
  switch (level) {
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
