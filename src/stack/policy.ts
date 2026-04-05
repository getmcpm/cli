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
          `since the lock file was created.`,
      };
    }
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
