/**
 * Trust policy enforcement — checks trust scores against stack file policy.
 *
 * All comparisons use normalized percentages (score / maxPossible) to avoid
 * false positives when external-scanner availability differs between machines.
 *
 * Pure functions, no I/O.
 */

import type { Policy, TrustSnapshot } from "./schema.js";
// Numeric bucket weight only, never a type or a scoring call: a lockfile's recorded
// `externalScanCredit` is this bucket's value at lock time, so validating it against a
// second copy of `20` here would silently stop matching if the bucket is re-weighted.
import { EXTERNAL_SCAN_MAX, maxAchievableBeforeHealthCheck } from "../scanner/trust-score.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * How a locked snapshot's native figure was obtained — `exact` when the lock records
 * enough to compute it, otherwise a conservative upper bound whose cause the block
 * message names, since the two causes have different remedies to explain.
 */
type RecoveryBasis = "exact" | "legacy-bound" | "out-of-range";

export interface PolicyCheckInput {
  readonly serverName: string;
  readonly currentScore: number;
  readonly currentMaxPossible: number;
  /**
   * The current score's mcpm-NATIVE figures (`nativeTrustScore(trust)`), used by
   * `blockOnScoreDrop` INSTEAD of the raw score (TODOS #35) — a caller-supplied
   * external scanner must never be able to mask a native drop. `minTrustScore`
   * deliberately keeps using the raw figure (a human threshold on the user's own
   * machine — the #33 carve-out), so these are unused when only that gate is active.
   * maxPossible is the native denominator (80).
   *
   * REQUIRED, and the drop check ALSO throws when they are missing. That is not
   * redundant: the type is erased at runtime and this function is exported through the
   * public `stack/index.ts` seam, so a JS or `as any` caller reaches the gate with
   * `undefined` — where `NaN < NaN` is false and the tripwire would silently PASS.
   * The type stops the mistake being written; the throw stops it being fatal.
   */
  readonly currentNativeScore: number;
  readonly currentNativeMaxPossible: number;
  readonly lockedSnapshot: TrustSnapshot | undefined;
  readonly policy: Policy | undefined;
  /**
   * Precomputed by assessReleaseAge — the caller MUST compute it with
   * minAgeHours = policy.minReleaseAgeHours when set, so the gate and the
   * assessment use the same threshold. Keeps policy.ts pure and clock-free.
   * `status` is an inlined structural copy of ReleaseAgeStatus (stack/ inlines
   * scanner/ SHAPES rather than importing them — same local-shape pattern as
   * ArgSchema; the one import from scanner/ is the numeric EXTERNAL_SCAN_MAX weight
   * above, which exists precisely so a bucket value is not duplicated).
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
    // `minTrustScore` is a PERCENTAGE, so the ceiling is 78 (62/80 = 77.5, and `toPct`
    // rounds), NOT 62. `up` scores with `healthCheckPassed: null` and no download count,
    // so a policy above that fails EVERY server on a flawless stack while the reason
    // below reads as a property of the server (TODOS #45).
    //
    // The ceiling goes through the SAME `toPct` as the server's score. That is what makes
    // the boundary exact: a flawless native server reports 78 and a policy of 78 passes
    // it, so 79 is the first unsatisfiable value. Computing the ceiling as a raw 77.5
    // would declare 78 unsatisfiable while the server it is compared against reports 78.
    //
    // Which ceiling applies is decided by this score's own denominator — the scorer's
    // record of whether it credited the external bucket (`externalCredited` is exactly
    // `maxPossible === FULL_MAX_POSSIBLE`). Derived from the scorer rather than a local
    // 80/100 literal so the two cannot drift apart.
    const creditedCeiling = maxAchievableBeforeHealthCheck(true);
    const ceiling =
      currentMaxPossible === creditedCeiling.maxPossible
        ? creditedCeiling
        : maxAchievableBeforeHealthCheck(false);
    const ceilingPct = toPct(ceiling.score, ceiling.maxPossible);
    if (policy.minTrustScore > ceilingPct) {
      // Scoped to servers scored the way THIS one was, not to the whole stack. Crediting
      // is decided per server, so a mixed-credit run legitimately contains both ceilings
      // and "every server in the stack will fail" would be false. And no number is
      // prescribed: `minTrustScore` lives in a committed stack file shared by the team,
      // while the ceiling that lowered it can be one developer's broken scanner — advising
      // an edit to a shared security gate on machine-local evidence is the wrong remedy.
      return {
        pass: false,
        reason:
          `policy.minTrustScore ${policy.minTrustScore}% is above ${ceilingPct}%, the highest ` +
          `percentage \`mcpm up\` can award a server scored the way "${serverName}" was ` +
          `(${currentPct}%). Trust is scored BEFORE any health check and mcpm reads no download ` +
          `count, so no server on this evidence path can reach the threshold — it refuses for ` +
          `what \`up\` cannot measure, not for the server's evidence.`,
      };
    }
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
  // A pre-#35 scanner-credited lock cannot have its exact native figure recovered, so
  // that path compares against a conservative UPPER BOUND and says so — it blocks
  // whenever a drop is possible and passes only when one is arithmetically impossible.
  // Re-locking replaces the bound with an exact baseline, which is why every bounded
  // verdict names it as the remedy.
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
          (lockedNative.basis === "legacy-bound"
            ? ` This lock predates native-evidence drop checks and was written with ` +
              `an external scanner credited, so the baseline is an upper bound — ` +
              `re-run \`mcpm lock\` to record an exact one.`
            : lockedNative.basis === "out-of-range"
              ? // Deliberately NOT phrased as tampering: an upward re-weighting of the
                // external bucket would make that accusation false for an older mcpm
                // reading a newer lock. Re-locking is the remedy either way.
                ` This lock records trust figures outside the range this version can ` +
                `interpret, so the baseline is an upper bound — re-run \`mcpm lock\` to ` +
                `record an exact one.`
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
 * Is a lockfile's recorded `externalScanCredit` a value this scorer could have
 * written?
 *
 * `mcpm-lock.yaml` lives in the user's own repository and carries no integrity
 * sidecar — the ~/.mcpm sidecars do not cover it — so a committed edit is the threat
 * model, and the schema deliberately does not bound this field (a `.max()` there makes
 * `parseLockFile`'s safeParse reject the WHOLE file, bricking up/verify/diff on an
 * otherwise-fine lock; see the note in schema.ts). Validation belongs here instead.
 *
 * `credit <= locked.score` is sound by construction, not a heuristic: a score is the
 * sum of four non-negative buckets and the credit IS one of them, so a legitimate lock
 * can never trip it.
 */
function isUsableCredit(credit: number, locked: TrustSnapshot, nativeMax: number): boolean {
  // A positive credit on a snapshot whose denominator was NOT widened is a combination
  // `lock` cannot produce: it writes `breakdown.externalScan`, which the scorer hard-
  // zeroes whenever it did not credit the bucket, and an uncredited score carries
  // maxPossible === nativeMax. Rejecting it therefore has zero false positives — and it
  // closes the disarm that survives every range check, since a credit of 20 added to an
  // untampered `{score: 62, maxPossible: 80}` lock is individually in range yet drops the
  // baseline from 78% to 53%.
  if (locked.maxPossible === nativeMax && credit > 0) return false;
  return credit >= 0 && credit <= EXTERNAL_SCAN_MAX && credit <= locked.score;
}

/**
 * Recover a locked snapshot's mcpm-NATIVE figure (score over the native
 * denominator) for the #35 drop check. ALWAYS returns a figure — when the exact
 * one is unrecoverable it returns a conservative UPPER BOUND.
 *
 * `nativeMax` is the current side's native denominator (80) — native scoring uses
 * one universal denominator, so the same value applies to the locked side.
 *
 * - `externalScanCredit` recorded AND usable (any lock this fix's mcpm wrote): native
 *   score is `score - credit`. Exact.
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
 *   impossible. Comparing against the upper bound is exactly right in both: it blocks
 *   whenever a drop is POSSIBLE and passes whenever it provably is not. Conservative
 *   for legacy locks by construction, and the remedy is always the same — re-lock to
 *   record an exact baseline.
 * - A credit outside the range this version can interpret takes that SAME bounded
 *   path, deliberately rather than being clamped into range. Clamping would fabricate
 *   a value in whichever direction the editor chose; equating "corrupt" with "absent"
 *   grants no capability anyone editing the file did not already have, since deleting
 *   the field was always available.
 *
 * Every branch exits through one clamp, because `score` and `maxPossible` are
 * themselves unbounded `z.number()`: without it a lock reading `score: 250` reported a
 * baseline of 288% and blocked every run.
 */
function recoverLockedNative(
  locked: TrustSnapshot,
  nativeMax: number,
): { readonly score: number; readonly maxPossible: number; readonly basis: RecoveryBasis } {
  const bounded = (score: number, basis: RecoveryBasis) => {
    const clamped = Math.max(0, Math.min(nativeMax, score));
    return {
      score: clamped,
      maxPossible: nativeMax,
      // A computation that had to be clamped was not exact, whatever produced it — an
      // out-of-range `score` reaches here the same way an out-of-range credit does,
      // since both are unbounded `z.number()`. Reporting it as exact would hand the
      // user the "you upgraded mcpm" remedy for a lock that actually needs re-locking.
      basis: basis === "exact" && clamped !== score ? ("out-of-range" as const) : basis,
    };
  };

  if (locked.externalScanCredit !== undefined) {
    return isUsableCredit(locked.externalScanCredit, locked, nativeMax)
      ? bounded(locked.score - locked.externalScanCredit, "exact")
      : bounded(locked.score, "out-of-range");
  }
  if (locked.maxPossible === nativeMax) {
    return bounded(locked.score, "exact");
  }
  return bounded(locked.score, "legacy-bound");
}
