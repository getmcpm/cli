/**
 * Trust policy enforcement — checks trust scores against stack file policy.
 *
 * All comparisons use normalized percentages (score / maxPossible) to avoid
 * false positives when external-scanner availability differs between machines.
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
  /**
   * The current score's mcpm-NATIVE figures (`nativeTrustScore(trust)`), used by
   * `blockOnScoreDrop` INSTEAD of the raw score (TODOS #35). Optional in the type,
   * but the drop check refuses to run without them rather than silently comparing
   * raw scores — a caller-supplied external scanner must never be able to mask a
   * native drop. `minTrustScore` deliberately keeps using the raw figure (a human
   * threshold on the user's own machine — the #33 carve-out), so these are unused
   * when only that gate is active. up.ts already computes `nativeTrust` and passes
   * both. maxPossible is the native denominator (80).
   */
  readonly currentNativeScore?: number;
  readonly currentNativeMaxPossible?: number;
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

  // Check score drop (requires locked snapshot).
  //
  // TODOS #35: this tripwire compares mcpm-NATIVE evidence only. Crediting the
  // external-scanner bucket does not merely add up to 20 points — it moves the
  // denominator 80 → 100, which raises the normalized percentage for EVERY native
  // score below 80. A caller-supplied `MCPM_EXTERNAL_SCANNER` that prints
  // `{"findings":[]}` is indistinguishable from a real clean scan, so a raw
  // comparison lets that unverifiable credit silently disarm the drop check
  // (reproduced: a server whose native evidence fell 75% → 69% passed with a fake
  // scanner). So the credit mcpm cannot verify must not clear the drop check, the
  // same rule `nativeTrustScore` applies to the hard floor.
  //
  // Deliberate consequence (not a bug): this is SYMMETRIC. mcpm cannot tell a real
  // external scanner's medium finding from a fake clean scan, so a genuine
  // external-scanner regression that lowers only the external bucket no longer
  // trips THIS tripwire either. That regression still shows up in the score itself
  // and in `mcpm audit`; the native drop check watches native evidence alone.
  // The unrecoverable-lock fallback below can also diverge from the native path for
  // the same underlying evidence on a pre-#35 scanner-credited lock — re-locking
  // reconciles it, which is why that path emits a re-lock instruction rather than a
  // silent verdict.
  if (policy.blockOnScoreDrop === true && lockedSnapshot !== undefined) {
    const { currentNativeScore, currentNativeMaxPossible } = input;
    if (
      currentNativeScore === undefined ||
      currentNativeMaxPossible === undefined
    ) {
      // Refuse rather than fall back to the raw comparison this fix exists to
      // retire. No production caller hits this (up.ts always supplies both); a
      // future one that enables the gate without them is a bug, surfaced loudly.
      throw new Error(
        "blockOnScoreDrop requires the current native trust figures " +
          "(currentNativeScore / currentNativeMaxPossible). This is a bug — " +
          "report it rather than working around it.",
      );
    }

    const lockedNative = recoverLockedNative(
      lockedSnapshot,
      currentNativeMaxPossible,
    );

    const curPct = toPct(currentNativeScore, currentNativeMaxPossible);
    const lockPct = toPct(lockedNative.score, lockedNative.maxPossible);
    if (curPct < lockPct) {
      return {
        pass: false,
        reason:
          `"${serverName}" trust score dropped from ${lockPct}% to ${curPct}% ` +
          `(mcpm-native evidence, excluding unverifiable external-scanner credit) ` +
          `since the lock file was created.` +
          (lockedNative.bounded
            ? ` This lock predates native-evidence drop checks and was written with ` +
              `an external scanner credited, so the baseline is an upper bound — ` +
              `re-run \`mcpm lock\` to record an exact one.`
            : ` If you recently upgraded mcpm, new scanner findings can lower ` +
              `scores — re-run \`mcpm lock\` to refresh snapshots if the drop is ` +
              `expected.`),
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

/**
 * Recover a locked snapshot's mcpm-NATIVE figure (score over the native
 * denominator) for the #35 drop check. ALWAYS returns a figure — when the exact
 * one is unrecoverable it returns a conservative UPPER BOUND, flagged `bounded`.
 *
 * `nativeMax` is the current side's native denominator (80) — native scoring uses
 * one universal denominator, so the same value applies to the locked side.
 *
 * - `externalScanCredit` recorded (any lock this fix's mcpm wrote): native score is
 *   `score - credit`, clamped at 0 against a hand-edited lock. Exact.
 * - No credit field but `maxPossible === nativeMax`: no scanner was credited at lock
 *   time, so the locked score is already native. Exact.
 * - No credit field and `maxPossible !== nativeMax` (a scanner was credited pre-#35):
 *   the exact figure is unrecoverable, but it is BOUNDED. The true native score is
 *   `score - credit` for some unknown `credit >= 0`, and it cannot exceed the native
 *   ceiling, so `native <= min(nativeMax, score)`.
 *
 *   Round 2 replaced a branch pair here (fail-closed when a current-side scanner was
 *   credited, raw-compare otherwise) with this bound, because BOTH branches were
 *   wrong in opposite directions: the raw compare failed OPEN on a genuine native
 *   drop, and the fail-closed branch blocked cases where a drop was arithmetically
 *   impossible (current native already at 80/80). Comparing against the upper bound
 *   is exactly right in both: it blocks whenever a drop is POSSIBLE and passes
 *   whenever it provably is not. Conservative for legacy locks by construction, and
 *   the remedy is always the same — re-lock to record an exact baseline.
 */
function recoverLockedNative(
  locked: TrustSnapshot,
  nativeMax: number,
): { readonly score: number; readonly maxPossible: number; readonly bounded: boolean } {
  if (locked.externalScanCredit !== undefined) {
    return {
      score: Math.max(0, locked.score - locked.externalScanCredit),
      maxPossible: nativeMax,
      bounded: false,
    };
  }
  if (locked.maxPossible === nativeMax) {
    return { score: locked.score, maxPossible: nativeMax, bounded: false };
  }
  return {
    score: Math.max(0, Math.min(nativeMax, locked.score)),
    maxPossible: nativeMax,
    bounded: true,
  };
}
