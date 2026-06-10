/**
 * Trust policy enforcement — checks trust scores against stack file policy.
 *
 * All comparisons use normalized percentages (score / maxPossible) to avoid
 * false positives when MCP-Scan availability differs between machines.
 *
 * Pure functions, no I/O.
 */

import type { Policy, TrustSnapshot } from "./schema.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PolicyCheckInput {
  readonly serverName: string;
  readonly currentScore: number;
  readonly currentMaxPossible: number;
  readonly lockedSnapshot: TrustSnapshot | undefined;
  readonly policy: Policy | undefined;
  /**
   * Precomputed by assessReleaseAge — the caller MUST compute it with
   * minAgeHours = policy.minReleaseAgeHours when set, so the gate and the
   * assessment use the same threshold. Keeps policy.ts pure and clock-free.
   * `status` is an inlined structural copy of ReleaseAgeStatus (stack/ does
   * not import from scanner/ — same local-shape pattern as ArgSchema).
   */
  readonly releaseAge?: {
    readonly ageHours: number | null;
    readonly status: "aged" | "fresh" | "future" | "unparseable" | "absent";
    readonly blocksArmedGate: boolean;
  };
  /** findings.some(f => f.type === "install-script") computed by the caller. */
  readonly hasInstallScriptFindings?: boolean;
}

export type PolicyResult =
  | { readonly pass: true }
  | { readonly pass: false; readonly reason: string };

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Check a server's trust score against the stack file policy.
 *
 * Returns `{ pass: true }` if the server passes all policy checks,
 * or `{ pass: false, reason }` with a human-readable explanation.
 */
export function checkTrustPolicy(input: PolicyCheckInput): PolicyResult {
  const { serverName, currentScore, currentMaxPossible, lockedSnapshot, policy } = input;

  if (policy === undefined) {
    return { pass: true };
  }

  const currentPct = toPct(currentScore, currentMaxPossible);

  // Check absolute floor
  if (policy.minTrustScore !== undefined && currentPct < policy.minTrustScore) {
    return {
      pass: false,
      reason:
        `"${serverName}" trust score ${currentPct}% is below the minimum ` +
        `policy threshold of ${policy.minTrustScore}%.`,
    };
  }

  // Check score drop (requires locked snapshot)
  if (policy.blockOnScoreDrop === true && lockedSnapshot !== undefined) {
    const lockedPct = toPct(lockedSnapshot.score, lockedSnapshot.maxPossible);

    if (currentPct < lockedPct) {
      return {
        pass: false,
        reason:
          `"${serverName}" trust score dropped from ${lockedPct}% to ${currentPct}% ` +
          `since the lock file was created. If you recently upgraded mcpm, new ` +
          `scanner findings can lower scores — re-run \`mcpm lock\` to refresh ` +
          `snapshots if the drop is expected.`,
      };
    }
  }

  // Check minimum release age (requires a caller-supplied assessment).
  // Fail-closed when armed: blocksArmedGate is also true for absent/unparseable
  // timestamps — there is no --allow-fresh for `up`; the policy itself is the
  // control, consistent with minTrustScore.
  if (
    policy.minReleaseAgeHours !== undefined &&
    input.releaseAge?.blocksArmedGate === true
  ) {
    const { ageHours, status } = input.releaseAge;
    if (status === "future") {
      return {
        pass: false,
        reason:
          `"${serverName}" has a publish timestamp in the future; treated as ` +
          `within the minimum release age of ${policy.minReleaseAgeHours} hour(s) ` +
          `required by policy.`,
      };
    }
    if (ageHours === null) {
      return {
        pass: false,
        reason:
          `"${serverName}" release is of unverifiable age (publish timestamp ` +
          `${status === "absent" ? "missing from registry metadata" : "could not be parsed"}), ` +
          `and the policy requires a minimum release age of ${policy.minReleaseAgeHours} hour(s).`,
      };
    }
    return {
      pass: false,
      reason:
        `"${serverName}" release is ${ageHours} hour(s) old, below the minimum ` +
        `release age of ${policy.minReleaseAgeHours} hour(s) required by policy.`,
    };
  }

  // Check install-script launchers (blunt by design: blocks every launcher
  // class that runs scripts, the pnpm strictDepBuilds analog).
  if (
    policy.blockInstallScripts === true &&
    input.hasInstallScriptFindings === true
  ) {
    return {
      pass: false,
      reason:
        `"${serverName}" resolves to a launcher that runs install scripts, ` +
        `and the policy blocks install scripts.`,
    };
  }

  return { pass: true };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toPct(score: number, maxPossible: number): number {
  if (maxPossible <= 0) return 0;
  return Math.round((score / maxPossible) * 100);
}
