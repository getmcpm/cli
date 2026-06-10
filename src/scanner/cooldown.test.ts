/**
 * Tests for src/scanner/cooldown.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * assessReleaseAge is a pure function: the clock is injected as epoch
 * milliseconds. All cases use a FIXED `NOW` constant — no Date.now(), no fake
 * timers — so the suite is deterministic forever.
 */

import { describe, it, expect } from "vitest";
import {
  assessReleaseAge,
  DEFAULT_MIN_RELEASE_AGE_HOURS,
  type ReleaseAgeInput,
  type ReleaseAgeStatus,
} from "./cooldown.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MS_PER_HOUR = 60 * 60 * 1000;
const NOW = new Date("2026-06-10T00:00:00Z").getTime();

function isoHoursBeforeNow(hours: number): string {
  return new Date(NOW - hours * MS_PER_HOUR).toISOString();
}

function makeInput(overrides: Partial<ReleaseAgeInput> = {}): ReleaseAgeInput {
  return {
    publishedAt: isoHoursBeforeNow(2),
    now: NOW,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Fresh release — the unconditional soft penalty
// ---------------------------------------------------------------------------

describe("assessReleaseAge — fresh release", () => {
  it("flags a 2-hour-old release as within the default cooldown", () => {
    const result = assessReleaseAge(makeInput());
    expect(result.ageHours).toBe(2);
    expect(result.status).toBe("fresh");
    expect(result.withinCooldown).toBe(true);
    expect(result.blocksArmedGate).toBe(true);
    expect(result.finding).toBeDefined();
    expect(result.finding?.severity).toBe("medium");
    expect(result.finding?.type).toBe("release-cooldown");
    expect(result.finding?.location).toBe("registry metadata");
    expect(result.finding?.message).toContain("24-hour release cooldown");
  });
});

// ---------------------------------------------------------------------------
// Boundary — exactly at the threshold
// ---------------------------------------------------------------------------

describe("assessReleaseAge — threshold boundary", () => {
  it("treats a release exactly 24h old as aged (no finding)", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(24) }));
    expect(result.ageHours).toBe(24);
    expect(result.status).toBe("aged");
    expect(result.withinCooldown).toBe(false);
    expect(result.blocksArmedGate).toBe(false);
    expect(result.finding).toBeUndefined();
  });

  it("treats a release 23h59m old as fresh (within cooldown)", () => {
    const result = assessReleaseAge(
      makeInput({ publishedAt: new Date(NOW - (24 * MS_PER_HOUR - 60_000)).toISOString() }),
    );
    expect(result.ageHours).toBe(23);
    expect(result.status).toBe("fresh");
    expect(result.withinCooldown).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Old release — well past the cooldown
// ---------------------------------------------------------------------------

describe("assessReleaseAge — aged release", () => {
  it("returns floored whole-hour age and no finding for a 31-day-old release", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(31 * 24) }));
    expect(result.ageHours).toBe(31 * 24);
    expect(result.status).toBe("aged");
    expect(result.withinCooldown).toBe(false);
    expect(result.finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Absent publishedAt — SPLIT SEMANTICS (score fail-open, armed-gate fail-closed)
// ---------------------------------------------------------------------------

describe("assessReleaseAge — absent publishedAt", () => {
  it("is score-fail-open but gate-fail-closed when publishedAt is undefined (the omit-_meta bypass test)", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: undefined }));
    expect(result.ageHours).toBeNull();
    expect(result.status).toBe("absent");
    expect(result.withinCooldown).toBe(false);
    expect(result.blocksArmedGate).toBe(true);
    expect(result.finding).toBeUndefined();
  });

  it("treats an empty-string publishedAt as absent", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: "" }));
    expect(result.ageHours).toBeNull();
    expect(result.status).toBe("absent");
    expect(result.withinCooldown).toBe(false);
    expect(result.blocksArmedGate).toBe(true);
    expect(result.finding).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Future timestamp — fail-safe (clock skew / forged metadata)
// ---------------------------------------------------------------------------

describe("assessReleaseAge — future timestamp", () => {
  it("treats a timestamp 1h in the future as within cooldown with ageHours 0", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(-1) }));
    expect(result.ageHours).toBe(0);
    expect(result.status).toBe("future");
    expect(result.withinCooldown).toBe(true);
    expect(result.blocksArmedGate).toBe(true);
    expect(result.finding?.message).toContain("in the future");
  });
});

// ---------------------------------------------------------------------------
// Unparseable timestamp — fail-safe
// ---------------------------------------------------------------------------

describe("assessReleaseAge — unparseable timestamp", () => {
  it("treats an unparseable publishedAt as within cooldown", () => {
    const result = assessReleaseAge(makeInput({ publishedAt: "not-a-date" }));
    expect(result.ageHours).toBeNull();
    expect(result.status).toBe("unparseable");
    expect(result.withinCooldown).toBe(true);
    expect(result.blocksArmedGate).toBe(true);
    expect(result.finding?.message).toContain("could not be parsed");
    expect(result.finding?.message).toContain('"not-a-date"');
  });
});

// ---------------------------------------------------------------------------
// blocksArmedGate truth table — the security disjunction lives here
// ---------------------------------------------------------------------------

describe("assessReleaseAge — blocksArmedGate truth table", () => {
  const rows: Array<{
    label: string;
    publishedAt: string | undefined;
    status: ReleaseAgeStatus;
    blocksArmedGate: boolean;
  }> = [
    { label: "fresh", publishedAt: isoHoursBeforeNow(1), status: "fresh", blocksArmedGate: true },
    { label: "future", publishedAt: isoHoursBeforeNow(-1), status: "future", blocksArmedGate: true },
    { label: "unparseable", publishedAt: "garbage", status: "unparseable", blocksArmedGate: true },
    { label: "absent", publishedAt: undefined, status: "absent", blocksArmedGate: true },
    { label: "aged", publishedAt: isoHoursBeforeNow(48), status: "aged", blocksArmedGate: false },
  ];

  for (const row of rows) {
    it(`${row.label} → blocksArmedGate ${row.blocksArmedGate}`, () => {
      const result = assessReleaseAge(makeInput({ publishedAt: row.publishedAt }));
      expect(result.status).toBe(row.status);
      expect(result.blocksArmedGate).toBe(row.blocksArmedGate);
    });
  }
});

// ---------------------------------------------------------------------------
// Custom thresholds
// ---------------------------------------------------------------------------

describe("assessReleaseAge — custom minAgeHours", () => {
  it("treats a 48h-old release as fresh under a 72h threshold", () => {
    const result = assessReleaseAge(
      makeInput({ publishedAt: isoHoursBeforeNow(48), minAgeHours: 72 }),
    );
    expect(result.ageHours).toBe(48);
    expect(result.status).toBe("fresh");
    expect(result.withinCooldown).toBe(true);
    expect(result.finding?.message).toContain("72-hour release cooldown");
  });

  it("defaults to DEFAULT_MIN_RELEASE_AGE_HOURS (24) when minAgeHours is omitted", () => {
    expect(DEFAULT_MIN_RELEASE_AGE_HOURS).toBe(24);
    // 30h old: aged under the default, would be fresh under any threshold > 30.
    const result = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(30) }));
    expect(result.status).toBe("aged");
    expect(result.withinCooldown).toBe(false);
  });

  it("minAgeHours 0: parseable past timestamps are aged; future/unparseable/absent still fail safe", () => {
    const aged = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(1), minAgeHours: 0 }));
    expect(aged.status).toBe("aged");
    expect(aged.withinCooldown).toBe(false);
    expect(aged.finding).toBeUndefined();

    const future = assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(-1), minAgeHours: 0 }));
    expect(future.status).toBe("future");
    expect(future.finding).toBeDefined();

    const unparseable = assessReleaseAge(makeInput({ publishedAt: "garbage", minAgeHours: 0 }));
    expect(unparseable.status).toBe("unparseable");
    expect(unparseable.finding).toBeDefined();

    const absent = assessReleaseAge(makeInput({ publishedAt: undefined, minAgeHours: 0 }));
    expect(absent.blocksArmedGate).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Determinism, immutability, copy hygiene
// ---------------------------------------------------------------------------

describe("assessReleaseAge — determinism and immutability", () => {
  it("returns equal but distinct results for the same input, without mutating it", () => {
    const input = makeInput();
    const snapshot = { ...input };
    const a = assessReleaseAge(input);
    const b = assessReleaseAge(input);
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    expect(a.finding).not.toBe(b.finding);
    expect(input).toEqual(snapshot);
  });
});

describe("assessReleaseAge — copy hygiene", () => {
  it("never uses the word 'malicious' in finding messages", () => {
    const withFindings = [
      assessReleaseAge(makeInput()),
      assessReleaseAge(makeInput({ publishedAt: isoHoursBeforeNow(-1) })),
      assessReleaseAge(makeInput({ publishedAt: "garbage" })),
    ];
    for (const result of withFindings) {
      expect(result.finding).toBeDefined();
      expect(result.finding?.message).not.toMatch(/malicious/i);
    }
  });
});
