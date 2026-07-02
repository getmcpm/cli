import { describe, expect, test } from "vitest";
import {
  ConfineProfileSchema,
  CONFINE_FORMAT_VERSION,
  emptyConfineStore,
  hashConfineProfile,
  type ConfineProfile,
} from "../profile.js";

const base: ConfineProfile = {
  tier: "standard",
  require_confine: false,
  read_deny: ["/home/u/.ssh"],
  write_allow: ["/tmp"],
  net: "none",
  scratch_dir: "/s",
  captured_at: "2026-01-01T00:00:00Z",
};

describe("hashConfineProfile", () => {
  test("is deterministic + 64-hex", () => {
    const h = hashConfineProfile(base);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(hashConfineProfile({ ...base })).toBe(h);
  });

  test("is INDEPENDENT of object key insertion order (YAML round-trip safety)", () => {
    // A store read via YAML may reorder keys; the marker hash was computed at
    // enable time. Both must agree, so the hash canonicalizes key order.
    const reordered = {
      captured_at: base.captured_at,
      net: base.net,
      write_allow: base.write_allow,
      scratch_dir: base.scratch_dir,
      read_deny: base.read_deny,
      require_confine: base.require_confine,
      tier: base.tier,
    } as ConfineProfile;
    expect(hashConfineProfile(reordered)).toBe(hashConfineProfile(base));
  });

  test("changes when any security-relevant field changes", () => {
    const h = hashConfineProfile(base);
    expect(hashConfineProfile({ ...base, net: "all" })).not.toBe(h);
    expect(hashConfineProfile({ ...base, read_deny: [] })).not.toBe(h);
    expect(hashConfineProfile({ ...base, require_confine: true })).not.toBe(h);
    expect(hashConfineProfile({ ...base, write_allow: ["/tmp", "/etc"] })).not.toBe(h);
  });
});

describe("ConfineProfileSchema", () => {
  test("accepts a well-formed standard profile", () => {
    expect(ConfineProfileSchema.safeParse(base).success).toBe(true);
  });

  test("rejects unknown keys (strict) and an unknown tier", () => {
    expect(ConfineProfileSchema.safeParse({ ...base, sneaky: 1 }).success).toBe(false);
    expect(ConfineProfileSchema.safeParse({ ...base, tier: "strict" }).success).toBe(false);
  });

  test("emptyConfineStore is a valid, versioned, empty store", () => {
    const s = emptyConfineStore();
    expect(s.format_version).toBe(CONFINE_FORMAT_VERSION);
    expect(s.servers).toEqual({});
  });
});
