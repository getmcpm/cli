/**
 * Trust score computation — pure function, no I/O.
 *
 * Takes findings and metadata, returns a structured TrustScore.
 * All objects returned are new (immutable pattern).
 */

import type { Finding } from "./tier1.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TrustScoreInput {
  findings: Finding[];
  healthCheckPassed: boolean | null; // null = not yet run
  hasExternalScanner: boolean;
  registryMeta: {
    isVerifiedPublisher?: boolean;
    publishedAt?: string;
    downloadCount?: number;
  };
}

export interface TrustScoreBreakdown {
  healthCheck: number;   // 0-30
  staticScan: number;    // 0-40
  externalScan: number;  // 0-20
  registryMeta: number;  // 0-10
}

export interface TrustScore {
  score: number;           // 0-100
  maxPossible: number;     // 80 if no external scanner, 100 otherwise
  level: "safe" | "caution" | "risky";
  breakdown: TrustScoreBreakdown;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const HEALTH_CHECK_PASS = 30;
const HEALTH_CHECK_FAIL = 0;
const HEALTH_CHECK_NULL = 15;

const STATIC_SCAN_MAX = 40;
const EXTERNAL_SCAN_MAX = 20;
const REGISTRY_META_MAX = 10;

/** Deductions per finding severity (applied to both static and external scan). */
const SEVERITY_DEDUCTIONS: Record<Finding["severity"], number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
};

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const PUBLISHED_AGE_DAYS = 30;
const DOWNLOAD_THRESHOLD = 100;

// ---------------------------------------------------------------------------
// Component scorers
// ---------------------------------------------------------------------------

function scoreHealthCheck(passed: boolean | null): number {
  if (passed === true) return HEALTH_CHECK_PASS;
  if (passed === false) return HEALTH_CHECK_FAIL;
  return HEALTH_CHECK_NULL;
}

function totalDeductions(findings: Finding[]): number {
  return findings.reduce((sum, f) => sum + SEVERITY_DEDUCTIONS[f.severity], 0);
}

function scoreStaticScan(findings: Finding[]): number {
  return Math.max(0, STATIC_SCAN_MAX - totalDeductions(findings));
}

function scoreExternalScan(hasExternalScanner: boolean, findings: Finding[]): number {
  if (!hasExternalScanner) return 0;
  return Math.max(0, EXTERNAL_SCAN_MAX - totalDeductions(findings));
}

function scoreRegistryMeta(meta: TrustScoreInput["registryMeta"]): number {
  let points = 0;

  if (meta.isVerifiedPublisher === true) {
    points += 4;
  }

  if (meta.publishedAt) {
    const publishedAge = Date.now() - new Date(meta.publishedAt).getTime();
    if (publishedAge > PUBLISHED_AGE_DAYS * MS_PER_DAY) {
      points += 3;
    }
  }

  if (typeof meta.downloadCount === "number" && meta.downloadCount > DOWNLOAD_THRESHOLD) {
    points += 3;
  }

  return Math.min(points, REGISTRY_META_MAX);
}

// ---------------------------------------------------------------------------
// Level threshold
// ---------------------------------------------------------------------------

function computeLevel(score: number, maxPossible: number): TrustScore["level"] {
  const ratio = score / maxPossible;
  if (ratio >= 0.8) return "safe";
  if (ratio >= 0.5) return "caution";
  return "risky";
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns true if any finding has critical or high severity.
 */
function hasCriticalOrHighFindings(findings: Finding[]): boolean {
  return findings.some((f) => f.severity === "critical" || f.severity === "high");
}

/**
 * Compute a trust score from findings and server metadata.
 * Returns a new TrustScore object — never mutates input.
 */
export function computeTrustScore(input: TrustScoreInput): TrustScore {
  // The external bucket is credited only when the scanner actually returned a
  // result we could READ — not merely because one was configured and exited 0.
  //
  // This is load-bearing, not defensive coding. `MCPM_EXTERNAL_SCANNER` names an
  // arbitrary executable, so without this gate any binary that exits 0 (say
  // `/bin/true`) would earn a silent 20/20 and add 20 RAW points. Two gates
  // compare raw scores: `mcpm install --min-trust`, and `HARD_TRUST_FLOOR` on the
  // no-human-in-loop MCP path, which is documented as a floor no caller-supplied
  // value can lower. An environment variable is caller-supplied — so crediting an
  // unverified scanner would let one lower that floor by 20 points. Requiring a
  // parseable result means a binary must genuinely speak the contract
  // (`{"findings": [...]}` on stdout) before its corroboration counts.
  //
  // A scanner that failed is treated as ABSENT rather than as a failing scan:
  // the bucket leaves `maxPossible` (80, not 100) instead of scoring 0 out of
  // 100, so a broken or misconfigured scanner never depresses a server's score.
  const externalCredited =
    input.hasExternalScanner &&
    !input.findings.some((f) => f.source === "external" && f.type === "scanner-error");

  const maxPossible = externalCredited ? 100 : 80;

  // Cap registryMeta to 0 when critical/high findings are present.
  // Attacker-controlled metadata (publishedAt, downloads) must not inflate
  // the score when the scan found serious issues.
  const registryMetaScore = hasCriticalOrHighFindings(input.findings)
    ? 0
    : scoreRegistryMeta(input.registryMeta);

  // Partition findings by source so each finding is deducted from exactly one
  // bucket. Tier-1 findings (source "static" or undefined) hit the static
  // sub-score; tier-2 external-scanner findings (source "external") hit the
  // external sub-score. Without this split, every finding was deducted from
  // BOTH buckets whenever an external scanner was present — making scores
  // artificially low precisely when the extra scanner was enabled.
  //
  // When no external scanner ran, the external sub-score is hard-zeroed and the
  // bucket is removed from maxPossible, so an "external"-tagged finding present
  // without a scanner would otherwise be silently dropped from ALL scoring and
  // deduct nothing. That should not happen in normal flow, but we route such
  // orphans into the static bucket as a safe fallback so they still deduct
  // rather than vanish.
  //
  // The one thing that must NOT fall through to the static bucket is a
  // scanner-error diagnostic from an uncredited scanner. It says the user's
  // scanner failed, not that the server is worse — deducting for it would make
  // a broken scanner quietly depress every server's score, which is the exact
  // opposite of treating a failed scanner as absent.
  const externalFindings = externalCredited
    ? input.findings.filter((f) => f.source === "external")
    : [];
  const staticFindings = externalCredited
    ? input.findings.filter((f) => f.source !== "external")
    : input.findings.filter((f) => f.type !== "scanner-error");

  const breakdown: TrustScoreBreakdown = {
    healthCheck: scoreHealthCheck(input.healthCheckPassed),
    staticScan: scoreStaticScan(staticFindings),
    externalScan: scoreExternalScan(externalCredited, externalFindings),
    registryMeta: registryMetaScore,
  };

  const score =
    breakdown.healthCheck +
    breakdown.staticScan +
    breakdown.externalScan +
    breakdown.registryMeta;

  const level = computeLevel(score, maxPossible);

  return { score, maxPossible, level, breakdown: { ...breakdown } };
}
