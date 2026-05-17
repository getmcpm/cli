/**
 * Tests for policy.ts — mute/unmute/pause helpers (v0.5.0 Step 7).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  readPolicy,
  writePolicy,
  setOverride,
  removeOverride,
  setPausedUntil,
  expireStale,
  parseDuration,
  isoOffsetFromNow,
  type GuardPolicyFile,
} from "../policy.js";
import { _resetCachedStorePath } from "../../store/index.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-guard-policy-test-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  _resetCachedStorePath();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  _resetCachedStorePath();
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("mutation helpers (pure)", () => {
  test("setOverride adds a new override", () => {
    const next = setOverride({}, "sig-x", "ignore");
    expect(next.signature_overrides).toEqual([{ id: "sig-x", action: "ignore" }]);
  });

  test("setOverride with expires_at carries it through", () => {
    const next = setOverride({}, "sig-x", "ignore", "2099-01-01T00:00:00Z");
    expect(next.signature_overrides?.[0]?.expires_at).toBe("2099-01-01T00:00:00Z");
  });

  test("setOverride replaces existing entry for same id", () => {
    let p: GuardPolicyFile = setOverride({}, "sig-x", "ignore");
    p = setOverride(p, "sig-x", "warn");
    expect(p.signature_overrides).toHaveLength(1);
    expect(p.signature_overrides?.[0]?.action).toBe("warn");
  });

  test("removeOverride drops the entry; if empty, removes the field", () => {
    let p: GuardPolicyFile = setOverride({}, "sig-x", "ignore");
    p = removeOverride(p, "sig-x");
    expect(p.signature_overrides).toBeUndefined();
  });

  test("removeOverride no-op when id is absent", () => {
    const p: GuardPolicyFile = setOverride({}, "sig-x", "ignore");
    const next = removeOverride(p, "other");
    expect(next).toBe(p);
  });

  test("setPausedUntil sets + clears", () => {
    let p: GuardPolicyFile = setPausedUntil({}, "2099-01-01T00:00:00Z");
    expect(p.paused_until).toBe("2099-01-01T00:00:00Z");
    p = setPausedUntil(p, null);
    expect(p.paused_until).toBeUndefined();
  });
});

describe("expireStale", () => {
  test("removes overrides whose expires_at is in the past", () => {
    const now = new Date("2026-05-17T00:00:00Z");
    const policy: GuardPolicyFile = {
      signature_overrides: [
        { id: "old", action: "ignore", expires_at: "2026-05-16T23:00:00Z" },
        { id: "ok", action: "ignore", expires_at: "2026-05-17T00:30:00Z" },
        { id: "perm", action: "ignore" },
      ],
    };
    const next = expireStale(policy, now);
    const ids = (next.signature_overrides ?? []).map((o) => o.id);
    expect(ids).toEqual(["ok", "perm"]);
  });

  test("clears paused_until if it's in the past", () => {
    const now = new Date("2026-05-17T00:00:00Z");
    const next = expireStale({ paused_until: "2026-05-16T23:00:00Z" }, now);
    expect(next.paused_until).toBeUndefined();
  });

  test("retains paused_until if it's in the future", () => {
    const now = new Date("2026-05-17T00:00:00Z");
    const next = expireStale({ paused_until: "2026-05-17T00:01:00Z" }, now);
    expect(next.paused_until).toBe("2026-05-17T00:01:00Z");
  });
});

describe("parseDuration", () => {
  test("seconds, minutes, hours, days", () => {
    expect(parseDuration("30s")).toBe(30_000);
    expect(parseDuration("5m")).toBe(300_000);
    expect(parseDuration("1h")).toBe(3_600_000);
    expect(parseDuration("2d")).toBe(2 * 86_400_000);
  });

  test("rejects invalid formats", () => {
    expect(() => parseDuration("forever")).toThrow();
    expect(() => parseDuration("5")).toThrow();
    expect(() => parseDuration("5min")).toThrow();
    expect(() => parseDuration("")).toThrow();
  });

  test("rejects zero (security review F3 — '0s' otherwise silently expired)", () => {
    expect(() => parseDuration("0s")).toThrow(/greater than zero/);
    expect(() => parseDuration("0m")).toThrow();
    expect(() => parseDuration("0d")).toThrow();
  });

  test("rejects overflow > 10 years (security review F3 — Date.toISOString RangeError)", () => {
    expect(() => parseDuration("3651d")).toThrow(/exceeds maximum/);
    expect(() => parseDuration("100000d")).toThrow(/exceeds maximum/);
  });
});

describe("isoOffsetFromNow", () => {
  test("produces an ISO 8601 string in the future", () => {
    const now = new Date("2026-05-17T00:00:00Z");
    expect(isoOffsetFromNow(60_000, now)).toBe("2026-05-17T00:01:00.000Z");
  });
});

describe("filesystem round-trip", () => {
  test("readPolicy on missing file returns empty policy", async () => {
    const p = await readPolicy();
    expect(p).toEqual({});
  });

  test("write → read round-trip preserves overrides + paused_until", async () => {
    let p: GuardPolicyFile = setOverride({}, "sig-x", "ignore", "2099-01-01T00:00:00Z");
    p = setPausedUntil(p, "2099-02-01T00:00:00Z");
    await writePolicy(p);
    const back = await readPolicy();
    expect(back.signature_overrides?.[0]?.id).toBe("sig-x");
    expect(back.paused_until).toBe("2099-02-01T00:00:00Z");
  });
});

describe("security review Step 7 — Zod validation + integrity sidecar", () => {
  test("readPolicy rejects numeric paused_until (security review F2)", async () => {
    // A malicious YAML write: `paused_until: 99999999999999` would otherwise
    // bypass all inspection because new Date(numeric) is year 5138.
    const { writeFileSync, mkdirSync } = await import("node:fs");
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "guard-policy.yaml"), "paused_until: 99999999999999\n", { mode: 0o600 });
    const policy = await readPolicy();
    // Should fall back to empty policy (Zod .catch({})) — strictly safer than
    // accepting the numeric value.
    expect(policy.paused_until).toBeUndefined();
  });

  test("readPolicy rejects malformed signature_overrides shape (security review F8)", async () => {
    const { writeFileSync, mkdirSync } = await import("node:fs");
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "guard-policy.yaml"), "signature_overrides: not-an-array\n", { mode: 0o600 });
    const policy = await readPolicy();
    expect(policy.signature_overrides).toBeUndefined();
  });

  test("readPolicy detects integrity tampering (security review F4)", async () => {
    const { PolicyIntegrityError } = await import("../policy.js");
    // First write a valid policy via writePolicy — this creates the sidecar.
    await writePolicy(setOverride({}, "owasp-mcp-2-instruction-injection-in-response", "ignore"));
    // Now silently tamper: replace the file content; the sidecar still has the old hash.
    const { writeFileSync } = await import("node:fs");
    writeFileSync(path.join(tmpHome, ".mcpm", "guard-policy.yaml"), "signature_overrides:\n  - id: evil\n    action: ignore\n");
    await expect(readPolicy()).rejects.toBeInstanceOf(PolicyIntegrityError);
  });
});
