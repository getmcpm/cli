/**
 * Release-age cooldown assessment — pure function, no I/O.
 *
 * `now` is injected as epoch milliseconds; this module NEVER reads the wall
 * clock (the existing Date.now() at trust-score.ts:94 is the anti-pattern
 * this module exists to avoid). All objects returned are new.
 *
 * SPLIT SEMANTICS (deliberate, security-reviewed): an ABSENT publishedAt is
 * fail-open for SCORING (withinCooldown=false, no finding — honest entries
 * without the official _meta block are not penalized) but fail-closed for
 * ARMED GATES (blocksArmedGate=true — a registry or compromised mirror must
 * not be able to defeat --min-release-age / policy.minReleaseAgeHours by
 * simply omitting the field, which OfficialMetaSchema marks .optional()
 * at src/registry/schemas.ts:72).
 */

import type { Finding } from "./tier1.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Curated default cooldown — mirrors the policy default minReleaseAgeHours: 24. */
export const DEFAULT_MIN_RELEASE_AGE_HOURS = 24;

const MS_PER_HOUR = 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Discriminant surfaced to gates and JSON envelopes (a future block must not masquerade as fresh). */
export type ReleaseAgeStatus = "aged" | "fresh" | "future" | "unparseable" | "absent";

export interface ReleaseAgeInput {
  /**
   * ISO-8601 publish timestamp from
   * _meta["io.modelcontextprotocol.registry/official"].publishedAt
   * (already surfaced by extractRegistryMeta, src/utils/format-trust.ts:16-24).
   * undefined when the registry omits the official meta block.
   */
  readonly publishedAt?: string;
  /** Current time as EPOCH MILLISECONDS — injected; never read internally. */
  readonly now: number;
  /** Cooldown threshold in hours. Defaults to DEFAULT_MIN_RELEASE_AGE_HOURS. */
  readonly minAgeHours?: number;
}

export interface ReleaseAgeAssessment {
  /** Whole hours since publication (floored, >= 0); null when publishedAt is missing or unparseable. */
  readonly ageHours: number | null;
  /** Which decision-table row fired — drives gate message variants and the JSON `reason` field. */
  readonly status: ReleaseAgeStatus;
  /**
   * Drives the SCORE finding only.
   * true  → release is younger than the threshold, OR timestamp is in the
   *         future / unparseable (fail-safe).
   * false → old enough, OR publishedAt absent (cannot assess — deliberately
   *         fail-open so servers without the official meta block are not
   *         penalized in scores).
   */
  readonly withinCooldown: boolean;
  /**
   * Drives ARMED gates (install --min-release-age, policy.minReleaseAgeHours).
   * Equals withinCooldown || status === "absent": an armed gate also blocks a
   * missing timestamp, closing the omit-_meta bypass. Computed HERE (not at
   * call sites) so the security-relevant disjunction lives in one pure,
   * directly-tested place.
   */
  readonly blocksArmedGate: boolean;
  /** Present exactly when withinCooldown === true. severity "medium", type "release-cooldown", location "registry metadata". */
  readonly finding?: Finding;
}

/** One decision-table row, before the blocksArmedGate disjunction is applied. */
type DecisionRow = Omit<ReleaseAgeAssessment, "blocksArmedGate">;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Pure + deterministic. Decision table:
 *   publishedAt undefined/""         → { ageHours: null, status: "absent",      withinCooldown: false, blocksArmedGate: true  }            (no finding — score fail-open, gate fail-closed)
 *   unparseable (NaN getTime)        → { ageHours: null, status: "unparseable", withinCooldown: true,  blocksArmedGate: true,  finding }   (fail-safe)
 *   future (publishedMs > now)       → { ageHours: 0,    status: "future",      withinCooldown: true,  blocksArmedGate: true,  finding }   (clock skew / forged ts, fail-safe)
 *   ageMs <  minAgeHours*MS_PER_HOUR → { ageHours: n,    status: "fresh",       withinCooldown: true,  blocksArmedGate: true,  finding }   (the unconditional soft penalty)
 *   ageMs >= threshold               → { ageHours: n,    status: "aged",        withinCooldown: false, blocksArmedGate: false }
 *
 * Severity rationale: medium (-5 via SEVERITY_DEDUCTIONS, source undefined →
 * staticScan bucket). high/critical would ALSO zero the registryMeta bucket
 * (computeTrustScore, trust-score.ts:139-141), stripping the verified-publisher
 * +4 from every honest fresh publisher and tripping install's red "risky"
 * double-confirm — disproportionate for an always-on signal. low (-2) would be
 * weaker than the +3 old-age bonus it inverts. Medium yields a net 8-point
 * swing vs a >30-day-old package (-5 penalty + missing +3 bonus).
 */
export function assessReleaseAge(input: ReleaseAgeInput): ReleaseAgeAssessment {
  const minAgeHours = input.minAgeHours ?? DEFAULT_MIN_RELEASE_AGE_HOURS;
  const row = classifyReleaseAge(input.publishedAt, input.now, minAgeHours);
  return {
    ...row,
    blocksArmedGate: row.withinCooldown || row.status === "absent",
  };
}

function classifyReleaseAge(
  publishedAt: string | undefined,
  now: number,
  minAgeHours: number,
): DecisionRow {
  if (publishedAt === undefined || publishedAt === "") {
    // Score fail-open / gate fail-closed — see SPLIT SEMANTICS in the header.
    return { ageHours: null, status: "absent", withinCooldown: false };
  }

  const publishedMs = new Date(publishedAt).getTime();
  if (Number.isNaN(publishedMs)) {
    // Fail-safe: a malformed official-meta timestamp is anomalous and must
    // not score better than an honest fresh release.
    return {
      ageHours: null,
      status: "unparseable",
      withinCooldown: true,
      finding: {
        severity: "medium",
        type: "release-cooldown",
        message: `Publish timestamp "${publishedAt}" could not be parsed — treated as within the ${minAgeHours}-hour release cooldown`,
        location: "registry metadata",
      },
    };
  }

  if (publishedMs > now) {
    // Fail-safe (clock skew or forged timestamp): ROADMAP F4 — a future
    // publishedAt is treated as within cooldown, never as a negative age.
    return {
      ageHours: 0,
      status: "future",
      withinCooldown: true,
      finding: {
        severity: "medium",
        type: "release-cooldown",
        message: `Publish timestamp "${publishedAt}" is in the future — treated as within the ${minAgeHours}-hour release cooldown`,
        location: "registry metadata",
      },
    };
  }

  const ageMs = now - publishedMs;
  const ageHours = Math.floor(ageMs / MS_PER_HOUR);

  if (ageMs < minAgeHours * MS_PER_HOUR) {
    return {
      ageHours,
      status: "fresh",
      withinCooldown: true,
      finding: {
        severity: "medium",
        type: "release-cooldown",
        message: `Published ${ageHours} hour(s) ago — newer than the ${minAgeHours}-hour release cooldown`,
        location: "registry metadata",
      },
    };
  }

  return { ageHours, status: "aged", withinCooldown: false };
}
