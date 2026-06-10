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

  it("blocks when normalized score dropped with blockOnScoreDrop", () => {
    // Locked: 85/100 = 85%. Current: 65/100 = 65%. Drop detected.
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 65,
      currentMaxPossible: 100,
      lockedSnapshot,
      policy: { blockOnScoreDrop: true },
    });
    expect(result.pass).toBe(false);
    if (!result.pass) {
      expect(result.reason).toContain("dropped");
      expect(result.reason).toContain("85%");
      expect(result.reason).toContain("65%");
    }
  });

  it("passes when score improved", () => {
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 90,
      currentMaxPossible: 100,
      lockedSnapshot,
      policy: { blockOnScoreDrop: true },
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

  it("compares normalized percentages across different maxPossible values", () => {
    // Locked with scanner: 85/100 = 85%
    // Current without scanner: 65/80 = 81.25% — should pass (81% > 85% is false, so this drops)
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 65,
      currentMaxPossible: 80,
      lockedSnapshot, // 85/100 = 85%
      policy: { blockOnScoreDrop: true },
    });
    // 81% < 85% → still a drop
    expect(result.pass).toBe(false);
  });

  it("passes normalized comparison when scanner unavailable but score equivalent", () => {
    // Locked with scanner: 85/100 = 85%
    // Current without scanner: 68/80 = 85% — equivalent, should pass
    const result = checkTrustPolicy({
      serverName: "test-server",
      currentScore: 68,
      currentMaxPossible: 80,
      lockedSnapshot, // 85/100 = 85%
      policy: { blockOnScoreDrop: true },
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
      lockedSnapshot,
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
