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

    if (lockedNative !== undefined) {
      const curPct = toPct(currentNativeScore, currentNativeMaxPossible);
      const lockPct = toPct(lockedNative.score, lockedNative.maxPossible);
      if (curPct < lockPct) {
        return {
          pass: false,
          reason:
            `"${serverName}" trust score dropped from ${lockPct}% to ${curPct}% ` +
            `(mcpm-native evidence, excluding unverifiable external-scanner credit) ` +
            `since the lock file was created. If you recently upgraded mcpm, new ` +
            `scanner findings can lower scores — re-run \`mcpm lock\` to refresh ` +
            `snapshots if the drop is expected.`,
        };
      }
    } else if (currentNativeMaxPossible !== currentMaxPossible) {
      // Pre-#35 lock with a scanner credited (maxPossible 100, no recorded credit):
      // the locked native figure is unrecoverable. AND the current side also has an
      // unverifiable scanner credited (its maxPossible exceeds the native
      // denominator) — the exact #35 lever. A raw comparison here would use the
      // fake-scanner-inflated current score against an inflated baseline, so a
      // `{"findings":[]}` stub could still mask a genuine native drop. With neither
      // side's native figure usable we cannot decide soundly, so FAIL CLOSED and
      // require a re-lock rather than reopen the exact hole this fix closes.
      return {
        pass: false,
        reason:
          `"${serverName}" cannot be checked for a trust-score drop: the lock predates ` +
          `native-evidence drop checks and was written with an external scanner ` +
          `credited, and one is credited now too — mcpm cannot separate verifiable ` +
          `evidence from unverifiable scanner credit on either side. Re-run ` +
          `\`mcpm lock\` to record a native baseline.`,
      };
    } else {
      // Pre-#35 lock with a scanner credited, but the CURRENT side has NO scanner
      // (currentScore is already native), so there is no fake-scanner lever on this
      // comparison. Fall back to the raw comparison — status quo, no worse than
      // before #35 — and note that a re-lock upgrades it to the native check.
      const lockedPct = toPct(lockedSnapshot.score, lockedSnapshot.maxPossible);
      if (currentPct < lockedPct) {
        return {
          pass: false,
          reason:
            `"${serverName}" trust score dropped from ${lockedPct}% to ${currentPct}% ` +
            `since the lock file was created. (This lock predates native-evidence ` +
            `drop checks — re-run \`mcpm lock\` to enable them.) If you recently ` +
            `upgraded mcpm, new scanner findings can lower scores.`,
        };
      }
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
 * denominator) for the #35 drop check, or `undefined` when it cannot be recovered.
 *
 * `nativeMax` is the current side's native denominator (80) — native scoring uses
 * one universal denominator, so the same value applies to the locked side.
 *
 * - `externalScanCredit` recorded (any lock this fix's mcpm wrote): native score is
 *   `score - credit`, clamped at 0 against a hand-edited lock.
 * - No credit field but `maxPossible === nativeMax`: no scanner was credited at lock
 *   time, so the locked score is already native.
 * - No credit field and `maxPossible !== nativeMax` (a scanner was credited pre-#35):
 *   the native figure is unrecoverable ⇒ `undefined`, and the caller falls back.
 */
function recoverLockedNative(
  locked: TrustSnapshot,
  nativeMax: number,
): { readonly score: number; readonly maxPossible: number } | undefined {
  if (locked.externalScanCredit !== undefined) {
    return {
      score: Math.max(0, locked.score - locked.externalScanCredit),
      maxPossible: nativeMax,
    };
  }
  if (locked.maxPossible === nativeMax) {
    return { score: locked.score, maxPossible: nativeMax };
  }
  return undefined;
}
