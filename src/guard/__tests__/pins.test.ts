/**
 * Tests for pins.ts — pin storage, integrity sidecar, mutation helpers
 * (v0.5.0 Next Step 6).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  hashToolDefinition,
  emptyPinsFile,
  upsertToolPin,
  clearServerPins,
  clearToolPin,
  acceptDrift,
  readPins,
  writePins,
  resetIntegrity,
  PinsIntegrityError,
  PINS_FORMAT_VERSION,
  type PinEntry,
  type PinsFile,
} from "../pins.js";
import { _resetCachedStorePath } from "../../store/index.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-guard-pins-test-"));
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

// ─────────────────────── pure functions ───────────────────────

describe("hashToolDefinition", () => {
  test("produces sha256: prefix + 64 hex chars", () => {
    const h = hashToolDefinition({ description: "x", schema: { type: "object" } });
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("same input → same hash", () => {
    const a = hashToolDefinition({ description: "x", schema: { a: 1, b: 2 } });
    const b = hashToolDefinition({ description: "x", schema: { a: 1, b: 2 } });
    expect(a).toBe(b);
  });

  test("key-order invariant via sorted canonical form", () => {
    const a = hashToolDefinition({ description: "x", schema: { a: 1, b: 2 } });
    const b = hashToolDefinition({ description: "x", schema: { b: 2, a: 1 } });
    expect(a).toBe(b);
  });

  test("differs when description differs", () => {
    const a = hashToolDefinition({ description: "x" });
    const b = hashToolDefinition({ description: "y" });
    expect(a).not.toBe(b);
  });

  test("differs when annotations differ", () => {
    const a = hashToolDefinition({ description: "x", annotations: { readOnlyHint: true } });
    const b = hashToolDefinition({ description: "x", annotations: { readOnlyHint: false } });
    expect(a).not.toBe(b);
  });

  test("null vs undefined inputs are equivalent", () => {
    const a = hashToolDefinition({ description: null, schema: null });
    const b = hashToolDefinition({});
    expect(a).toBe(b);
  });
});

describe("emptyPinsFile", () => {
  test("returns a file with the current format version and no servers", () => {
    const pins = emptyPinsFile();
    expect(pins.format_version).toBe(PINS_FORMAT_VERSION);
    expect(pins.servers).toEqual({});
  });
});

describe("mutation helpers", () => {
  const makeEntry = (hash: string | null): PinEntry => ({
    current_hash: hash,
    previous_hashes: [],
    captured_at: "2026-05-17T00:00:00Z",
    captured_via: "install",
    signature_list_version: "v0.5.0",
  });

  test("upsertToolPin adds + replaces without mutating input", () => {
    const orig: PinsFile = emptyPinsFile();
    const next = upsertToolPin(orig, "fs", "read_file", makeEntry("sha256:abc"));
    expect(next.servers.fs?.read_file?.current_hash).toBe("sha256:abc");
    expect(orig.servers.fs).toBeUndefined();
  });

  test("clearToolPin removes only the named tool", () => {
    let p = emptyPinsFile();
    p = upsertToolPin(p, "fs", "read", makeEntry("a"));
    p = upsertToolPin(p, "fs", "write", makeEntry("b"));
    const next = clearToolPin(p, "fs", "read");
    expect(next.servers.fs?.read).toBeUndefined();
    expect(next.servers.fs?.write?.current_hash).toBe("b");
  });

  test("clearServerPins removes the whole server", () => {
    let p = emptyPinsFile();
    p = upsertToolPin(p, "fs", "read", makeEntry("a"));
    p = upsertToolPin(p, "git", "commit", makeEntry("b"));
    const next = clearServerPins(p, "fs");
    expect(next.servers.fs).toBeUndefined();
    expect(next.servers.git?.commit?.current_hash).toBe("b");
  });

  test("acceptDrift moves current_hash into previous_hashes + sets new current", () => {
    let p = emptyPinsFile();
    p = upsertToolPin(p, "fs", "read", makeEntry("sha256:old"));
    const next = acceptDrift(p, "fs", "read", "sha256:new");
    const entry = next.servers.fs?.read;
    expect(entry?.current_hash).toBe("sha256:new");
    expect(entry?.previous_hashes).toEqual(["sha256:old"]);
  });

  test("acceptDrift on a missing entry is a no-op", () => {
    const p = emptyPinsFile();
    const next = acceptDrift(p, "fs", "read", "sha256:x");
    expect(next).toBe(p);
  });
});

// ─────────────────────── filesystem round-trip ───────────────────────

describe("readPins / writePins", () => {
  test("readPins on missing file returns empty pins", async () => {
    const pins = await readPins();
    expect(pins).toEqual(emptyPinsFile());
  });

  test("write → read round-trip preserves data", async () => {
    let pins = emptyPinsFile();
    pins = upsertToolPin(pins, "fs", "read", {
      current_hash: "sha256:abc",
      previous_hashes: [],
      captured_at: "2026-05-17T00:00:00Z",
      captured_via: "install",
      signature_list_version: "v0.5.0",
    });
    await writePins(pins);
    const back = await readPins();
    expect(back.servers.fs?.read?.current_hash).toBe("sha256:abc");
  });

  test("writePins also writes the integrity sidecar", async () => {
    await writePins(emptyPinsFile());
    const sidecar = path.join(tmpHome, ".mcpm", "pins.json.integrity");
    expect(existsSync(sidecar)).toBe(true);
    expect(readFileSync(sidecar, "utf-8")).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("readPins throws PinsIntegrityError when pins.json is tampered with", async () => {
    await writePins(emptyPinsFile());
    // Modify pins.json behind the sidecar's back.
    const filePath = path.join(tmpHome, ".mcpm", "pins.json");
    writeFileSync(filePath, '{"format_version": 1, "servers": {"evil": {}}}\n');
    await expect(readPins()).rejects.toBeInstanceOf(PinsIntegrityError);
  });

  test("readPins with no sidecar (first-run) succeeds without integrity check", async () => {
    // Write pins.json directly without using writePins (so no sidecar exists).
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "pins.json"), JSON.stringify(emptyPinsFile()), { mode: 0o600 });
    const pins = await readPins();
    expect(pins.servers).toEqual({});
  });

  test("resetIntegrity refreshes the sidecar after manual edit", async () => {
    await writePins(emptyPinsFile());
    const filePath = path.join(tmpHome, ".mcpm", "pins.json");
    // User-edited the file directly.
    writeFileSync(filePath, '{"format_version": 1, "servers": {"hand-added": {}}}\n');
    await resetIntegrity();
    // Should now read without throwing.
    const pins = await readPins();
    expect(pins.servers["hand-added"]).toEqual({});
  });

  test("readPins throws on format_version mismatch", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "pins.json"), '{"format_version": 99, "servers": {}}', { mode: 0o600 });
    await expect(readPins()).rejects.toThrow(/format_version mismatch/);
  });
});
