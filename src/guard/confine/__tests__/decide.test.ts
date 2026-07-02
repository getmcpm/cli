/**
 * The spawn confine decision table — the security-critical core of F1. Every row
 * of the table (docs plan §2) is asserted, including the tamper/strip/store-wiped
 * rows that make the marker↔store binding load-bearing.
 */

import { describe, expect, test } from "vitest";
import { decideConfine } from "../decide.js";
import { hashConfineProfile, type ConfineProfile } from "../profile.js";

const mkProfile = (over: Partial<ConfineProfile> = {}): ConfineProfile => ({
  tier: "standard",
  require_confine: false,
  read_deny: ["/home/u/.ssh", "/home/u/.aws"],
  write_allow: ["/tmp", "/home/u/.npm"],
  net: "none",
  scratch_dir: "/home/u/.mcpm/sandbox/srv-abcd1234",
  captured_at: "2026-01-01T00:00:00Z",
  ...over,
});

describe("decideConfine — the 9-row table", () => {
  test("row 1: profile + matching hash + backend up → confine", () => {
    const profile = mkProfile();
    const d = decideConfine({
      profile,
      markerHash: hashConfineProfile(profile),
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("confine");
    expect(d.event).toBe("confine-applied");
  });

  test("row 2: matching hash + backend DOWN + not required → unconfined + warn event", () => {
    const profile = mkProfile();
    const d = decideConfine({
      profile,
      markerHash: hashConfineProfile(profile),
      markerRequired: false,
      backendAvailable: false,
    });
    expect(d.action).toBe("unconfined");
    expect(d.event).toBe("confine-backend-missing");
  });

  test("row 2 (required via profile): matching hash + backend DOWN + require_confine → fail-closed", () => {
    const profile = mkProfile({ require_confine: true });
    const d = decideConfine({
      profile,
      markerHash: hashConfineProfile(profile),
      markerRequired: false,
      backendAvailable: false,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-backend-missing");
  });

  test("row 2 (required via marker): matching hash + backend DOWN + markerRequired → fail-closed", () => {
    const profile = mkProfile(); // require_confine false in store...
    const d = decideConfine({
      profile,
      markerHash: hashConfineProfile(profile),
      markerRequired: true, // ...but the marker says required (survives store edit)
      backendAvailable: false,
    });
    expect(d.action).toBe("fail-closed");
  });

  test("row 3: profile + MISMATCHED hash → fail-closed ALWAYS (backend up, not required)", () => {
    const profile = mkProfile();
    const d = decideConfine({
      profile,
      markerHash: "f".repeat(64), // wrong
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-hash-mismatch");
  });

  test("row 4: profile + hash STRIPPED + required → fail-closed (strip-bypass)", () => {
    const profile = mkProfile({ require_confine: true });
    const d = decideConfine({
      profile,
      markerHash: null,
      markerRequired: true,
      backendAvailable: true,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-marker-stripped");
  });

  test("row 4b: profile + hash STRIPPED + not required → unconfined + warn (hybrid)", () => {
    const profile = mkProfile();
    const d = decideConfine({
      profile,
      markerHash: null,
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("unconfined");
    expect(d.event).toBe("confine-marker-stripped");
  });

  test("row 4 (required via STORE only): require_confine profile + stripped hash + markerRequired false → fail-closed", () => {
    // An attacker strips --confine-profile-hash but not --confine-required is
    // moot here — the STORE's require_confine alone must still fail closed.
    const profile = mkProfile({ require_confine: true });
    const d = decideConfine({
      profile,
      markerHash: null,
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-marker-stripped");
  });

  test("row 5: NO profile (store wiped) + markerRequired → fail-closed", () => {
    const d = decideConfine({
      profile: null,
      markerHash: "a".repeat(64),
      markerRequired: true,
      backendAvailable: true,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-profile-missing");
  });

  test("row 5b: NO profile + marker hash present + not required → unconfined + warn", () => {
    const d = decideConfine({
      profile: null,
      markerHash: "a".repeat(64),
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("unconfined");
    expect(d.event).toBe("confine-profile-missing");
  });

  test("row 6: no profile + no marker tokens → unconfined, NO event (today's server)", () => {
    const d = decideConfine({
      profile: null,
      markerHash: null,
      markerRequired: false,
      backendAvailable: true,
    });
    expect(d.action).toBe("unconfined");
    expect(d.event).toBeUndefined();
  });

  test("row 7: no profile + hash stripped but --confine-required remained → fail-closed", () => {
    const d = decideConfine({
      profile: null,
      markerHash: null,
      markerRequired: true,
      backendAvailable: false,
    });
    expect(d.action).toBe("fail-closed");
    expect(d.event).toBe("confine-profile-missing");
  });
});
