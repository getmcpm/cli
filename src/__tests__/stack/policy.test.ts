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
});
