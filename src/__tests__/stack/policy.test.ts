import { describe, it, expect } from "vitest";
import { checkTrustPolicy } from "../../stack/policy.js";
import type { TrustSnapshot } from "../../stack/schema.js";

describe("checkTrustPolicy", () => {
  const lockedSnapshot: TrustSnapshot = {
    score: 85,
    maxPossible: 100,
    level: "safe",
    assessedAt: "2026-04-05T10:00:00Z",
  };

  it("passes when score is above minTrustScore", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minTrustScore: 60 },
    });
    expect(result.pass).toBe(true);
  });

  it("blocks when score is below minTrustScore", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 40,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minTrustScore: 60 },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("below the minimum");
      expect(result.reason).toContain("40%");
      expect(result.reason).toContain("60%");
    }
  });

  // --- #35: blockOnScoreDrop compares mcpm-native evidence ------------------

  // A lock this fix's mcpm wrote records externalScanCredit, so the locked native
  // figure is recoverable. Native 60/80 = 75% (score 80, of which 20 is scanner).
  const lockedWithCredit: TrustSnapshot = {
    score: 80,
    maxPossible: 100,
    level: "safe",
    assessedAt: "2026-08-05T10:00:00Z",
    externalScanCredit: 20,
  };

  it("blocks a genuine native drop (recoverable lock)", () => {
    // Locked native 60/80 = 75%; current native 55/80 = 69%. Drop.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 55,
      currentMaxPossible: 80,
      currentNativeScore: 55,
      currentNativeMaxPossible: 80,
      lockedSnapshot: lockedWithCredit,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("dropped");
      expect(result.reason).toContain("75%");
      expect(result.reason).toContain("69%");
      expect(result.reason).toContain("native");
    }
  });

  it("a fake external scanner does NOT disarm the drop check (#35)", () => {
    // The exploit: native evidence genuinely fell 75% → 69%, but a caller-supplied
    // MCPM_EXTERNAL_SCANNER printed {"findings":[]}, adding 20 points AND moving the
    // denominator 80→100. Raw: 75/100 = 75% vs locked raw 80/100 = 80% — under the
    // old raw comparison the inflation would have made this closer to a pass; the
    // native comparison ignores the unverifiable credit and still blocks.
    const gamed = checkTrustPolicy({
      serverName: "evil",
      currentScore: 75, // 55 native + 20 fake scanner
      currentMaxPossible: 100,
      currentNativeScore: 55, // the credit is stripped for the tripwire
      currentNativeMaxPossible: 80,
      lockedSnapshot: lockedWithCredit, // native 60/80 = 75%
      policy: { blockOnScoreDrop: true },
    });
    expect(gamed.pass).toBe(false); // 69% < 75% on native evidence

    // And with no scanner at all the verdict is identical — proving the fake
    // scanner's credit changed nothing about the tripwire.
    const honest = checkTrustPolicy({
      serverName: "evil",
      currentScore: 55,
      currentMaxPossible: 80,
      currentNativeScore: 55,
      currentNativeMaxPossible: 80,
      lockedSnapshot: lockedWithCredit,
      policy: { blockOnScoreDrop: true },
    });
    expect(honest.pass).toBe(false);
  });

  it("passes when native evidence is equivalent (recoverable lock)", () => {
    // Locked native 60/80 = 75%; current native 60/80 = 75%. Not a drop.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 60,
      currentMaxPossible: 80,
      currentNativeScore: 60,
      currentNativeMaxPossible: 80,
      lockedSnapshot: lockedWithCredit,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(true);
  });

  it("passes when native score improved (recoverable lock)", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 72,
      currentMaxPossible: 80,
      currentNativeScore: 72,
      currentNativeMaxPossible: 80,
      lockedSnapshot: lockedWithCredit, // native 75%
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(true);
  });

  // A lock with no scanner credited at lock time (maxPossible 80): the score is
  // already native, recoverable without the credit field.
  it("recovers native from a no-scanner lock (maxPossible 80, no credit field)", () => {
    const noScannerLock: TrustSnapshot = {
      score: 60,
      maxPossible: 80,
      level: "safe",
      assessedAt: "2026-08-05T10:00:00Z",
    };
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 55,
      currentMaxPossible: 80,
      currentNativeScore: 55,
      currentNativeMaxPossible: 80,
      lockedSnapshot: noScannerLock, // native 60/80 = 75%
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false); // 69% < 75%
    if (!result.pass) expect(result.reason).toContain("native");
  });

  // --- #35 back-compat: pre-fix lock with a scanner, native unrecoverable ----

  it("compares against a bounded baseline on a pre-#35 lock (scanner credited, no field)", () => {
    // lockedSnapshot: 85/100, no externalScanCredit ⇒ exact native unrecoverable.
    // Bounded upper baseline = min(nativeMax 80, score 85) = 80/80 = 100%.
    // Current native 65/80 = 81% < 100% ⇒ drop; reason says the baseline is a bound.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 65,
      currentMaxPossible: 80,
      currentNativeScore: 65,
      currentNativeMaxPossible: 80,
      lockedSnapshot, // 85/100, no credit field
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("81%");
      expect(result.reason).toContain("upper bound");
      expect(result.reason).toContain("mcpm lock");
    }
  });

  it("blocks a native drop on an unrecoverable lock when the current side has a scanner (#35 lever)", () => {
    // The hole the first fix left: an unrecoverable pre-#35 lock (scanner credited,
    // no field) AND a current-side scanner. Native genuinely fell (47/80 = 59%) but
    // the fake scanner banks +20 → raw current 67/100 = 67% ≥ locked raw 65% PASSED.
    // Bounded baseline = min(80, 65) = 65 ⇒ 59% < 81% ⇒ blocked.
    const preFixLock: TrustSnapshot = {
      score: 65,
      maxPossible: 100, // scanner credited at lock time, no externalScanCredit field
      level: "caution",
      assessedAt: "2026-08-06T00:00:00Z",
    };
    const result = checkTrustPolicy({
      serverName: "evil",
      currentScore: 67, // 47 native + 20 fake scanner
      currentMaxPossible: 100,
      currentNativeScore: 47,
      currentNativeMaxPossible: 80,
      lockedSnapshot: preFixLock,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) expect(result.reason).toContain("upper bound");
  });

  it("blocks a real native drop on an unrecoverable lock even with NO current scanner (round-2 fail-open)", () => {
    // Round 2: the old raw fallback compared 88% (current raw, native denominator)
    // against 85% (locked raw, 100 denominator) and PASSED — while native evidence
    // had genuinely fallen from a possible 80/80 to 70/80. Apples-to-oranges
    // denominators hid it. Bounded baseline = min(80, 85) = 80 ⇒ 88% < 100% ⇒ block.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 80, // no scanner configured now
      currentNativeScore: 70,
      currentNativeMaxPossible: 80,
      lockedSnapshot, // 85/100, no credit field ⇒ bounded at min(80,85)=80
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
  });

  it("passes when the bounded baseline is genuinely not a drop (round-2 false block)", () => {
    // Post-merge review #11. This previously fed currentNativeScore: 80 — a state no
    // production caller can produce, because `up` scores with healthCheckPassed: null
    // and so caps current native at 62. A pass certified only by an unreachable
    // fixture certifies nothing: the bound could be mutated freely and this still
    // passed.
    //
    // Reachable version: a pre-#35 lock that scored 55/100 bounds to min(80, 55) = 55,
    // i.e. 69%; current native 62/80 = 78% is ABOVE it, so there is no drop. Mutation
    // caught: dropping the Math.min so the bound becomes the raw 55 → still 69%, no —
    // dropping the clamp entirely (bound = maxPossible 80 ⇒ 100%) flips this to block.
    const lowPreFixLock: TrustSnapshot = {
      score: 55,
      maxPossible: 100,
      level: "caution",
      assessedAt: "2026-08-06T00:00:00Z",
    };
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 62,
      currentMaxPossible: 80,
      currentNativeScore: 62, // the real audit/up ceiling, not the unreachable 80
      currentNativeMaxPossible: 80,
      lockedSnapshot: lowPreFixLock,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(true);
  });

  // --- #3: a lockfile-supplied credit must not be able to steer the tripwire ------

  it("ignores an externalScanCredit larger than the locked score (disarm attempt)", () => {
    // mcpm-lock.yaml lives in the user's repo and carries no integrity sidecar, so a
    // committed edit is the threat. Setting the credit above the score zeroed the
    // recovered baseline (Math.max(0, 82 - 999) = 0 ⇒ 0%), after which no current
    // score could ever be "below" it — the tripwire was dead while score and level
    // stayed pristine in the diff a reviewer reads.
    //
    // The credit can never legitimately exceed the score: the score is the sum of four
    // non-negative buckets and the credit IS one of them.
    const tampered: TrustSnapshot = {
      score: 82,
      maxPossible: 100,
      level: "safe",
      assessedAt: "2026-08-06T00:00:00Z",
      externalScanCredit: 999,
    };
    const result = checkTrustPolicy({
      serverName: "evil",
      currentScore: 20,
      currentMaxPossible: 80,
      currentNativeScore: 20, // a catastrophic native drop
      currentNativeMaxPossible: 80,
      lockedSnapshot: tampered,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
  });

  it("ignores a negative externalScanCredit (jam attempt)", () => {
    // The other direction: a negative credit inflated the baseline past 100%
    // (82 - -20 = 102/80 = 128%), so every subsequent `up` blocked every server with a
    // nonsensical percentage until the user re-locked.
    const tampered: TrustSnapshot = {
      score: 62,
      maxPossible: 100,
      level: "caution",
      assessedAt: "2026-08-06T00:00:00Z",
      externalScanCredit: -20,
    };
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 62,
      currentMaxPossible: 80,
      currentNativeScore: 62,
      currentNativeMaxPossible: 80,
      lockedSnapshot: tampered,
      policy: { blockOnScoreDrop: true },
    });
    // Treated as unrecoverable ⇒ bounded at min(80, 62) = 62 ⇒ 78% vs 78% ⇒ no drop.
    expect(result.pass).toBe(true);
  });

  it("never reports a baseline above 100% even for an out-of-range locked score", () => {
    // `score` and `maxPossible` are themselves unbounded z.number(), so the clamp has
    // to live at the exit rather than on the credit alone.
    const absurd: TrustSnapshot = {
      score: 250,
      maxPossible: 100,
      level: "safe",
      assessedAt: "2026-08-06T00:00:00Z",
      externalScanCredit: 20,
    };
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 62,
      currentMaxPossible: 80,
      currentNativeScore: 62,
      currentNativeMaxPossible: 80,
      lockedSnapshot: absurd,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      // 100% is legitimate (the clamp lands on nativeMax); anything ABOVE it is the
      // bug — the unclamped form reported "dropped from 288%".
      const percentages = [...result.reason.matchAll(/(\d+)%/g)].map((m) => Number(m[1]));
      expect(percentages.length).toBeGreaterThan(0);
      expect(Math.max(...percentages)).toBeLessThanOrEqual(100);
    }
  });

  it("throws if blockOnScoreDrop is active without native figures", () => {
    // A future caller must not silently fall back to the raw comparison this fix
    // retired — the gate refuses to run rather than reopen the hole.
    expect(() =>
      checkTrustPolicy({
        serverName: "test-server",
        currentScore: 65,
        currentMaxPossible: 100,
        lockedSnapshot: lockedWithCredit,
        policy: { blockOnScoreDrop: true },
      }),
    ).toThrow(/native trust figures/);
  });

  it("does not require native figures when only minTrustScore is set", () => {
    // The #33 carve-out: minTrustScore stays a raw human threshold, so the drop
    // branch (and its native requirement) never runs.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot,
      policy: { minTrustScore: 60 },
    });
    expect(result.pass).toBe(true);
  });

  it("passes when no policy is defined", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 10,
      currentMaxPossible: 100,
      lockedSnapshot,
      policy: undefined,
    });
    expect(result.pass).toBe(true);
  });

  it("handles minTrustScore with normalized percentage correctly", () => {
    // minTrustScore: 60 means 60% floor
    // Current: 50/80 = 62.5% — above 60%, should pass
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 50,
      currentMaxPossible: 80,
      lockedSnapshot: undefined,
      policy: { minTrustScore: 60 },
    });
    expect(result.pass).toBe(true);
  });

  // --- F4: minReleaseAgeHours gate -----------------------------------------

  it("blocks a fresh release when minReleaseAgeHours is set", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
      releaseAge: { ageHours: 2, status: "fresh", blocksArmedGate: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("2 hour(s) old");
      expect(result.reason).toContain("minimum release age of 24 hour(s)");
    }
  });

  it("blocks an unverifiable release age (absent or unparseable timestamp)", () => {
    const absent = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
      releaseAge: { ageHours: null, status: "absent", blocksArmedGate: true },
    });
    expect(absent.pass).toBe(false);
    if (!absent.pass) {
      expect(absent.reason).toContain("unverifiable age");
      expect(absent.reason).toContain("missing from registry metadata");
    }

    const unparseable = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
      releaseAge: { ageHours: null, status: "unparseable", blocksArmedGate: true },
    });
    expect(unparseable.pass).toBe(false);
    if (!unparseable.pass) {
      expect(unparseable.reason).toContain("unverifiable age");
      expect(unparseable.reason).toContain("could not be parsed");
    }
  });

  it("blocks a future publish timestamp with a dedicated reason", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
      releaseAge: { ageHours: 0, status: "future", blocksArmedGate: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("in the future");
      expect(result.reason).not.toContain("hour(s) old");
    }
  });

  it("passes an aged release, and the gate is strictly opt-in", () => {
    const aged = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
      releaseAge: { ageHours: 100, status: "aged", blocksArmedGate: false },
    });
    expect(aged.pass).toBe(true);

    // Policy without minReleaseAgeHours never blocks on release age.
    const unarmed = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minTrustScore: 10 },
      releaseAge: { ageHours: 2, status: "fresh", blocksArmedGate: true },
    });
    expect(unarmed.pass).toBe(true);
  });

  it("passes when the caller did not compute releaseAge (optional field)", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minReleaseAgeHours: 24 },
    });
    expect(result.pass).toBe(true);
  });

  // --- F4: blockInstallScripts gate ----------------------------------------

  it("blocks install-script launchers only when blockInstallScripts is true and findings exist", () => {
    const blocked = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 70,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { blockInstallScripts: true },
      hasInstallScriptFindings: true,
    });
    expect(blocked.pass).toBe(false);
    if (!blocked.pass) {
      expect(blocked.reason).toContain(
        "resolves to a launcher that runs install scripts"
      );
    }

    // Flag set but no findings → pass.
    expect(
      checkTrustPolicy({
        serverName: "test-server",
        currentScore: 70,
        currentMaxPossible: 100,
        lockedSnapshot: undefined,
        policy: { blockInstallScripts: true },
        hasInstallScriptFindings: false,
      }).pass
    ).toBe(true);

    // Findings present but flag unset/false → pass (undefined ≡ false).
    expect(
      checkTrustPolicy({
        serverName: "test-server",
        currentScore: 70,
        currentMaxPossible: 100,
        lockedSnapshot: undefined,
        policy: {},
        hasInstallScriptFindings: true,
      }).pass
    ).toBe(true);
    expect(
      checkTrustPolicy({
        serverName: "test-server",
        currentScore: 70,
        currentMaxPossible: 100,
        lockedSnapshot: undefined,
        policy: { blockInstallScripts: false },
        hasInstallScriptFindings: true,
      }).pass
    ).toBe(true);
  });

  // --- F4: blockOnScoreDrop migration copy ----------------------------------

  it("appends the re-lock remediation hint to the blockOnScoreDrop reason", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 65,
      currentMaxPossible: 100,
      currentNativeScore: 55,
      currentNativeMaxPossible: 80,
      lockedSnapshot: {
        score: 80,
        maxPossible: 100,
        level: "safe",
        assessedAt: "2026-08-05T10:00:00Z",
        externalScanCredit: 20,
      },
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("re-run");
      expect(result.reason).toContain("mcpm lock");
    }
  });

  it("returns the minTrustScore failure first when multiple checks would fail", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 40,
      currentMaxPossible: 100,
      lockedSnapshot: undefined,
      policy: { minTrustScore: 60, minReleaseAgeHours: 24 },
      releaseAge: { ageHours: 2, status: "fresh", blocksArmedGate: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("below the minimum");
      expect(result.reason).not.toContain("minimum release age");
    }
  });

  it("passes when policy is undefined even if releaseAge would block an armed gate (regression)", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 10,
      currentMaxPossible: 100,
      lockedSnapshot,
      policy: undefined,
      releaseAge: { ageHours: 1, status: "fresh", blocksArmedGate: true },
      hasInstallScriptFindings: true,
    });
    expect(result.pass).toBe(true);
  });
});
