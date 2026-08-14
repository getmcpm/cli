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
/**
 * Exported for `stack/policy.ts`, which validates a lockfile's recorded
 * `externalScanCredit` against it. That field is this bucket's value at lock time,
 * so the ceiling has to be the one this scorer actually awards — a second copy of
 * `20` in the validator would silently stop matching if the bucket is re-weighted.
 */
export const EXTERNAL_SCAN_MAX = 20;
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

/**
 * The score reachable from mcpm's OWN evidence — health check, tier-1 static
 * scan, registry metadata. Also the `maxPossible` reported when no external
 * scanner was credited, and the denominator `nativeTrustScore` reports.
 *
 * Derived rather than written as `80` so the three buckets stay the single
 * source of truth if any of them is ever re-weighted.
 */
const NATIVE_MAX_POSSIBLE = HEALTH_CHECK_PASS + STATIC_SCAN_MAX + REGISTRY_META_MAX;
const FULL_MAX_POSSIBLE = NATIVE_MAX_POSSIBLE + EXTERNAL_SCAN_MAX;

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
  // The external bucket is credited only when the scanner returned a result we
  // could READ — not merely because one was configured and exited 0.
  //
  // Be precise about what this does and does not buy, because the raw score
  // feeds `mcpm install --min-trust` and the MCP `HARD_TRUST_FLOOR`. It stops
  // the ACCIDENTAL inflation: a binary that is not a scanner (`/bin/true` exits
  // 0 and says nothing), a typo'd path, a scanner that broke after an upgrade.
  // Those would otherwise bank a silent 20/20 for doing nothing.
  //
  // It does NOT stop deliberate self-deception, and cannot. Anyone who can set
  // MCPM_EXTERNAL_SCANNER can also write a two-line script that prints
  // `{"findings": []}`, which is indistinguishable from a real clean scan —
  // mcpm has no way to verify an arbitrary executable did any work. So the
  // external bucket is, and should be read as, "a scanner the USER chose to
  // trust reported this", never as independent corroboration mcpm validated.
  //
  // Because it cannot be verified, that bucket is excluded from the safety
  // floors the no-human-in-loop MCP surface enforces — see `nativeTrustScore`
  // below (TODOS #33). It still informs the score every human-facing surface
  // displays and compares; it just cannot CLEAR a floor on its own.
  //
  // A scanner whose result we could not read is treated as ABSENT rather than as
  // a failing scan: the bucket leaves `maxPossible` (80, not 100) instead of
  // scoring 0 out of 100. Note the honest comparison — that is "no worse than
  // having no scanner", NOT "no change": a stack that was scoring against a
  // working scanner and whose scanner then breaks does lose those points, and a
  // raw `--min-trust` gate will see the drop.
  const externalCredited =
    input.hasExternalScanner &&
    !input.findings.some((f) => f.source === "external" && f.type === "scanner-error");

  const maxPossible = externalCredited ? FULL_MAX_POSSIBLE : NATIVE_MAX_POSSIBLE;

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
    : input.findings.filter((f) => !(f.type === "scanner-error" && f.source === "external"));

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

/**
 * Did this score bank the external-scanner bucket?
 *
 * The scorer widens the denominator to `FULL_MAX_POSSIBLE` exactly when it credited
 * the bucket, so `maxPossible` IS the record of that decision — which makes this the
 * one honest way to ask after the fact.
 *
 * Note what it is NOT: `checkScannerAvailable()`. That is a bare `<cmd> --version`
 * exit-0 probe, while crediting additionally requires that the scanner returned output
 * the scorer could READ. A scanner that answers `--version` but cannot scan a registry
 * server name emits a `scanner-error` finding and is credited nowhere, so the two
 * predicates disagree precisely when a scanner is half-working — the case that made
 * `audit --fix`'s ceiling delete flawless servers.
 *
 * Crediting is decided PER SERVER (a `scanner-error` is per invocation), so a single
 * run can legitimately contain both, and callers reducing over a run must decide which
 * direction is safe rather than assume uniformity.
 */
export function externalCredited(trust: TrustScore): boolean {
  return trust.maxPossible === FULL_MAX_POSSIBLE;
}

/** A trust score with third-party credit mcpm cannot verify removed. */
export interface NativeTrustScore {
  /** The score, less the external-scanner bucket's credit. */
  score: number;
  /** Denominator for `score` — always the three mcpm-native buckets. */
  maxPossible: number;
  /** Points excluded — 0 when no external scanner was credited. */
  excludedExternalCredit: number;
}

/**
 * The part of a trust score mcpm produced itself, for evaluating SAFETY FLOORS
 * (TODOS #33).
 *
 * `HARD_TRUST_FLOOR` is documented as a gate no caller-supplied value can
 * lower. `MCPM_EXTERNAL_SCANNER` is caller-supplied — it names an arbitrary
 * executable — and a two-line script that prints `{"findings": []}` is
 * indistinguishable from a real clean scan, so before this the bucket's 20
 * points could lift a server over the floor. Reproduced: two critical tier-1
 * findings and no health check score 15 (blocked); with such a script
 * configured they score 35, and `mcpm_up` installed the server.
 *
 * The rule: third-party corroboration mcpm cannot verify may INFORM a score,
 * but must not be able to CLEAR a safety floor. So the floor is compared
 * against `score - breakdown.externalScan`.
 *
 * Note the asymmetry is deliberate and one-directional WITH RESPECT TO THE
 * EXTERNAL SCANNER. Removing only the bucket's CREDIT leaves every penalty an
 * external finding carries outside that bucket — most importantly the
 * critical/high cap on `registryMeta` — intact. An external scanner can
 * therefore still push a server DOWN through the floor, which is the
 * fail-closed direction, but can never push one UP through it.
 *
 * That is a claim about THIS bucket, not about the native figure in general.
 * The native buckets are not attacker-proof by construction: on the MCP surface
 * the caller also supplies the stack file, and a stack `policy` knob that
 * suppresses a native-bucket finding raises the figure this returns. The
 * release-age cooldown was exactly that (`minReleaseAgeHours: 0`, native
 * 20 → 25 against a floor of 25) and is now ignored whenever a floor is in
 * effect — see `processServer` in `src/commands/up.ts`. Any FUTURE policy knob
 * that can suppress a healthCheck / staticScan / registryMeta finding needs the
 * same treatment; this function cannot enforce that on its own.
 *
 * This is deliberately NOT applied to `mcpm install --min-trust`, to a stack
 * file's `policy.minTrustScore`, or to `mcpm audit --fix`. Those are thresholds a
 * human chose on their own machine, where the same person configures both the
 * threshold and the scanner; subtracting their scanner's points there would
 * surprise legitimate users for no security gain.
 *
 * `audit --fix` is excluded for a SECOND, independently sufficient reason, and it
 * is the one that decided the case (TODOS #35 sibling, resolved 2026-08-12): it is
 * the only score-gated DESTRUCTIVE gate in the CLI. Every other site on this list
 * REFUSES; that one DELETES servers from the user's IDE configs, so subtracting the
 * bucket there removes more rather than refusing more. Measured over 1,199 live
 * registry entries: a native filter changes 0 servers at audit's default threshold
 * and deletes every server once the threshold passes audit's native ceiling of 62.
 *
 * So the test is agent-reachability AND refuse-not-delete, not agent-reachability
 * alone — note that `policy.minTrustScore` is on this list yet IS reachable by an
 * agent through `mcpm_up` (`handlers.ts`), so the older one-line framing ("the
 * floors this guards are the ones an AI agent, not a human, is on the other side
 * of") was already too neat.
 */
export function nativeTrustScore(trust: TrustScore): NativeTrustScore {
  const score = trust.score - trust.breakdown?.externalScan;

  // Both gate expressions are `native.score < floor`, and `NaN < 25` is FALSE —
  // so a TrustScore carrying a partial `breakdown` would fail OPEN and install.
  // No production caller can produce one today (every wiring binds the real
  // `computeTrustScore`), but the lock file's `TrustSnapshot` is a
  // breakdown-less, TrustScore-shaped object that already exists and is already
  // read by a sibling gate, so the trajectory is short. Refuse rather than
  // coerce: a `?? 0` fallback would CREDIT the missing bucket as zero and pass.
  if (!Number.isFinite(score)) {
    throw new Error(
      "Cannot evaluate a trust floor: the trust score has no usable breakdown. " +
      "This is a bug — report it rather than working around it.",
    );
  }

  return {
    score,
    maxPossible: NATIVE_MAX_POSSIBLE,
    excludedExternalCredit: trust.breakdown.externalScan,
  };
}

/**
 * The best score any server could reach at a gate that runs BEFORE the health check.
 *
 * Every score-threshold gate in the product — `install --min-trust`,
 * `policy.minTrustScore`, `audit --fix --min-trust`, the MCP install floor, and
 * `mcpm_setup`'s pre-filter (a FIFTH gate that does not forward its threshold to the
 * install gate, so it needs its own check) — scores
 * with `healthCheckPassed: null` (the check runs after install, if at all), and
 * `extractRegistryMeta` never returns a download count anywhere in the product. So 18 of
 * the 80 mcpm-native points are unreachable AT THOSE CALL SITES: the best possible server
 * tops out at 62/80, or 82/100 once the external bucket is credited. A threshold above
 * that is unsatisfiable by construction — every server is refused, forever, and the
 * message blames the server rather than the threshold.
 *
 * The metadata here is deliberately the most FAVOURABLE a server could present, which
 * makes this a property of the CALL SITE (what a gate can measure) rather than of any one
 * server. Folding a server's own `publishedAt` / registry status in instead would move
 * the ceiling per server — on `audit --fix` that let a publisher republish to become
 * unremovable, inverting F4's release-age cooldown.
 *
 * ABSOLUTE vs PERCENTAGE is not interchangeable and has bitten this code before. Callers
 * comparing a raw score use `.score` (62); `policy.minTrustScore` is a PERCENTAGE and
 * must use `.score / .maxPossible * 100` (77.5). Passing 62 to the percentage gate would
 * silently under-guard by 15 points.
 *
 * Known residual, unchanged from TODOS #42: 62 is reachable only by a pypi/oci server.
 * Every npm package draws one `low` `install-script` finding for the `npx -y` launcher
 * class, so a clean npm server tops out at 60. `--min-trust 61..62` therefore stays
 * unsatisfiable for an all-npm stack — narrower than the band this closes, and stated
 * rather than papered over. In PERCENTAGE units, which is what `policy.minTrustScore`
 * reads, the same residual is 60/80 = 75% against a ceiling of 78: a policy of 76..78
 * is unsatisfiable for an all-npm stack while this guard reports it as satisfiable.
 *
 * Callers must key this on whether the score was CREDITED (`externalCredited`), never on
 * scanner AVAILABILITY. Those are different predicates: availability is a bare
 * `<cmd> --version` probe, while the scorer credits the bucket only when the scanner also
 * returned output it could read. An availability-keyed ceiling reads 82 for a run capped
 * at 62.
 */
export function maxAchievableBeforeHealthCheck(hasExternalScanner: boolean): TrustScore {
  return computeTrustScore({
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
