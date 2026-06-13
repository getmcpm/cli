/**
 * Tests for the unguarded-consent store (H9 Part A).
 *
 * Pure set-logic helpers + a small read/write store mirroring pins.ts
 * discipline (atomic write, 0o600). The store records which URL/HTTP-transport
 * servers the user has explicitly consented to run UNGUARDED (no relay).
 *
 *  - isNewUnguarded(current, previous): true iff current ⊄ previous (an ADDITION).
 *    Removal does NOT count as "new" (removals reduce risk → no re-warn).
 *  - read/write round-trips; missing file → empty set; sorted + deduped.
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import {
  isNewUnguarded,
  mergeUnguarded,
  readUnguardedConsent,
  writeUnguardedConsent,
  UNGUARDED_FILENAME,
} from "../unguarded.js";
import { _resetCachedStorePath } from "../../store/index.js";

// ──────────────────────── pure set logic ────────────────────────

describe("isNewUnguarded — set-change detection", () => {
  test("addition (current ⊄ previous) is new", () => {
    expect(isNewUnguarded(["a", "b"], ["a"])).toBe(true);
  });

  test("subset (current ⊆ previous) is NOT new", () => {
    expect(isNewUnguarded(["a"], ["a", "b"])).toBe(false);
  });

  test("equal sets are NOT new", () => {
    expect(isNewUnguarded(["a", "b"], ["b", "a"])).toBe(false);
  });

  test("removal alone (current shrinks) is NOT new", () => {
    // previous had a,b; current only a → a removal, not an addition.
    expect(isNewUnguarded(["a"], ["a", "b"])).toBe(false);
  });

  test("empty current is never new", () => {
    expect(isNewUnguarded([], ["a"])).toBe(false);
    expect(isNewUnguarded([], [])).toBe(false);
  });

  test("a server new against an empty previous set is new", () => {
    expect(isNewUnguarded(["a"], [])).toBe(true);
  });
});

describe("mergeUnguarded — union, sorted, deduped", () => {
  test("union of two sets is sorted and deduped", () => {
    expect(mergeUnguarded(["b", "a"], ["a", "c"])).toEqual(["a", "b", "c"]);
  });

  test("merging with empty returns the other, sorted/deduped", () => {
    expect(mergeUnguarded(["b", "b", "a"], [])).toEqual(["a", "b"]);
  });
});

// ──────────────────────── store I/O ────────────────────────

describe("readUnguardedConsent / writeUnguardedConsent", () => {
  let tmpHome: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-unguarded-test-"));
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

  test("missing file → empty set", async () => {
    const got = await readUnguardedConsent();
    expect(got).toEqual([]);
  });

  test("write then read round-trips (sorted + deduped)", async () => {
    await writeUnguardedConsent(["zeta", "alpha", "alpha"]);
    const got = await readUnguardedConsent();
    expect(got).toEqual(["alpha", "zeta"]);
  });

  test("the store file is created with 0o600 perms", async () => {
    await writeUnguardedConsent(["one"]);
    const file = path.join(tmpHome, ".mcpm", UNGUARDED_FILENAME);
    const st = statSync(file);
    // Mask to permission bits; 0o600 = owner read/write only.
    expect(st.mode & 0o777).toBe(0o600);
  });

  test("the store serializes a { servers: string[] } shape", async () => {
    await writeUnguardedConsent(["b", "a"]);
    const file = path.join(tmpHome, ".mcpm", UNGUARDED_FILENAME);
    const parsed = JSON.parse(readFileSync(file, "utf-8")) as { servers: string[] };
    expect(parsed.servers).toEqual(["a", "b"]);
  });
});
