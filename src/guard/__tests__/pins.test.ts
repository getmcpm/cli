/**
 * Tests for pins.ts — pin storage, integrity sidecar, mutation helpers
 * (v0.5.0 Next Step 6).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
  readFileSync,
  existsSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  hashToolDefinition,
  fieldHashesOf,
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
  handshakeFieldHashesOf,
  handshakeCapabilityKeys,
  hashHandshake,
  upsertHandshakePin,
  lookupHandshake,
  type PinEntry,
  type PinsFile,
  type HandshakePinEntry,
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

describe("fieldHashesOf (H4)", () => {
  test("each field is a sha256: hex string", () => {
    const fh = fieldHashesOf({
      description: "x",
      schema: { type: "object" },
      annotations: { readOnlyHint: true },
    });
    expect(fh.description).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fh.schema).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fh.annotations).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("stable under schema key reordering (same canonical leaves)", () => {
    const a = fieldHashesOf({ description: "x", schema: { a: 1, b: 2 } });
    const b = fieldHashesOf({ description: "x", schema: { b: 2, a: 1 } });
    expect(a).toEqual(b);
  });

  test("null/undefined fields collapse to the empty/null canonical form", () => {
    const a = fieldHashesOf({ description: null, schema: null, annotations: null });
    const b = fieldHashesOf({});
    expect(a).toEqual(b);
  });

  // INVARIANT: hashToolDefinition(x) changes ⟺ at least one fieldHashesOf(x)
  // field changes. Both derive from the SAME canonical leaves (description ?? "",
  // schema ?? null, annotations ?? null) via sortedReplacer, so a whole-hash
  // change cannot exist without a field-hash change and vice versa.
  test("whole-hash ⟺ field-hash invariant over varied tool defs", () => {
    const variants: Array<{ description?: string | null; schema?: unknown; annotations?: unknown }> = [
      { description: "a" },
      { description: "b" },
      { description: "a", schema: { type: "object" } },
      { description: "a", schema: { type: "string" } },
      { description: "a", schema: { type: "object", properties: { x: { type: "number" } } } },
      { description: "a", annotations: { readOnlyHint: true } },
      { description: "a", annotations: { readOnlyHint: false } },
      { description: "a", annotations: { destructiveHint: true } },
      { description: "", schema: null, annotations: null },
      { description: null },
      { description: "long ".repeat(50) },
      { description: "a", schema: { enum: ["x", "y", "z"] } },
      { description: "a", schema: { enum: ["x", "y"] } },
      { description: "a", schema: [1, 2, 3] },
      { description: "a", schema: [3, 2, 1] },
      { description: "c", schema: { nested: { deep: { value: 1 } } } },
      { description: "c", schema: { nested: { deep: { value: 2 } } } },
      { description: "d", annotations: { title: "Read" } },
      { description: "d", annotations: { title: "Write" } },
      { description: "unicode 日本語", schema: { type: "object" } },
    ];
    for (let i = 0; i < variants.length; i++) {
      for (let j = 0; j < variants.length; j++) {
        const wholeEq = hashToolDefinition(variants[i]!) === hashToolDefinition(variants[j]!);
        const fa = fieldHashesOf(variants[i]!);
        const fb = fieldHashesOf(variants[j]!);
        const fieldsEq =
          fa.description === fb.description &&
          fa.schema === fb.schema &&
          fa.annotations === fb.annotations;
        expect(wholeEq).toBe(fieldsEq);
      }
    }
  });
});

describe("emptyPinsFile", () => {
  test("returns a file with the current format version and no servers", () => {
    const pins = emptyPinsFile();
    expect(pins.format_version).toBe(PINS_FORMAT_VERSION);
    expect(pins.servers).toEqual({});
  });
});

// ─────────────────────── H5: handshake-pin helpers ───────────────────────

describe("handshakeFieldHashesOf (H5)", () => {
  test("capabilities + serverName are each a sha256: hex string", () => {
    const fh = handshakeFieldHashesOf({
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: "fs" },
    });
    expect(fh.capabilities).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(fh.serverName).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  // BOUNDARY: serverInfo.version is DELIBERATELY excluded — pinning it would warn
  // on every benign release. Two handshakes differing ONLY in version must hash equal.
  test("excludes serverInfo.version (a version-only bump produces identical field hashes)", () => {
    const a = handshakeFieldHashesOf({
      capabilities: { tools: {} },
      serverInfo: { name: "fs", version: "1.0.0" },
    });
    const b = handshakeFieldHashesOf({
      capabilities: { tools: {} },
      serverInfo: { name: "fs", version: "9.9.9" },
    });
    expect(a).toEqual(b);
  });

  test("capability change moves the capabilities hash, leaves serverName hash", () => {
    const a = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    const b = handshakeFieldHashesOf({
      capabilities: { tools: {}, sampling: {} },
      serverInfo: { name: "fs" },
    });
    expect(a.capabilities).not.toBe(b.capabilities);
    expect(a.serverName).toBe(b.serverName);
  });

  test("identity change moves the serverName hash, leaves capabilities hash", () => {
    const a = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    const b = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "evil" } });
    expect(a.serverName).not.toBe(b.serverName);
    expect(a.capabilities).toBe(b.capabilities);
  });

  test("missing capabilities / non-string name collapse to canonical defaults (null / empty)", () => {
    const a = handshakeFieldHashesOf({});
    const b = handshakeFieldHashesOf({ capabilities: null, serverInfo: { name: 42 } });
    expect(a).toEqual(b);
  });
});

describe("handshakeCapabilityKeys (H5)", () => {
  test("returns sorted top-level capability keys", () => {
    const keys = handshakeCapabilityKeys({
      capabilities: { tools: {}, sampling: {}, resources: {} },
    });
    expect(keys).toEqual(["resources", "sampling", "tools"]);
  });

  test("non-object / missing capabilities → []", () => {
    expect(handshakeCapabilityKeys({})).toEqual([]);
    expect(handshakeCapabilityKeys({ capabilities: null })).toEqual([]);
    expect(handshakeCapabilityKeys({ capabilities: "nope" as unknown })).toEqual([]);
  });
});

describe("hashHandshake (H5)", () => {
  test("derives a stable whole-hash from the field hashes", () => {
    const f = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    expect(hashHandshake(f)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(hashHandshake(f)).toBe(hashHandshake(f));
  });

  test("a field-hash change changes the whole-hash", () => {
    const a = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    const b = handshakeFieldHashesOf({ capabilities: { tools: {}, sampling: {} }, serverInfo: { name: "fs" } });
    expect(hashHandshake(a)).not.toBe(hashHandshake(b));
  });
});

describe("upsertHandshakePin / lookupHandshake (H5)", () => {
  const makeHandshakeEntry = (): HandshakePinEntry => {
    const fields = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    return {
      current_hash: hashHandshake(fields),
      previous_hashes: [],
      captured_at: "2026-06-14T00:00:00Z",
      captured_via: "first-session",
      signature_list_version: "v0.5.0",
      field_hashes: fields,
      capability_keys: ["tools"],
    };
  };

  test("upsertHandshakePin adds without mutating input", () => {
    const orig = emptyPinsFile();
    const next = upsertHandshakePin(orig, "fs", makeHandshakeEntry());
    expect(next.handshakes?.fs?.current_hash).toMatch(/^sha256:/);
    expect(orig.handshakes).toBeUndefined();
  });

  test("lookupHandshake returns the entry for a known server", () => {
    const pins = upsertHandshakePin(emptyPinsFile(), "fs", makeHandshakeEntry());
    expect(lookupHandshake(pins, "fs")?.capability_keys).toEqual(["tools"]);
    expect(lookupHandshake(pins, "absent")).toBeUndefined();
  });

  // F13: a `__proto__`-named server key must be contained via Object.hasOwn —
  // no prototype-pollution, and a lookup of an UNRELATED server must not resolve
  // Object.prototype's inherited members.
  test("lookupHandshake resists prototype pollution via Object.hasOwn (F13)", () => {
    const pins = upsertHandshakePin(emptyPinsFile(), "__proto__", makeHandshakeEntry());
    // The entry is an OWN property, not poured onto the prototype.
    expect(Object.hasOwn(pins.handshakes ?? {}, "__proto__")).toBe(true);
    // A lookup of an unrelated key must NOT resolve via the prototype chain.
    expect(lookupHandshake(pins, "constructor")).toBeUndefined();
    expect(lookupHandshake(pins, "toString")).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  test("lookupHandshake on a pre-H5 pins file (no handshakes key) returns undefined", () => {
    expect(lookupHandshake(emptyPinsFile(), "fs")).toBeUndefined();
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

  test("resetIntegrity returns false when there is no pins.json (nothing to refresh)", async () => {
    expect(await resetIntegrity()).toBe(false);
  });

  test("resetIntegrity returns true and rewrites the sidecar when pins.json exists", async () => {
    await writePins(emptyPinsFile());
    expect(await resetIntegrity()).toBe(true);
    const sidecar = path.join(tmpHome, ".mcpm", "pins.json.integrity");
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

  // Fix 1 (HIGH): resetIntegrity must route its sidecar write through the same
  // hardened atomic writer as writePins, so a pre-placed symlink at the sidecar
  // path cannot redirect the write onto an attacker-chosen target.
  test("resetIntegrity refuses to write through a symlinked sidecar", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // pins.json exists (so reset has something to hash).
    writeFileSync(path.join(dir, "pins.json"), '{"format_version": 1, "servers": {}}\n', {
      mode: 0o600,
    });
    const outside = path.join(tmpHome, "outside-sidecar");
    writeFileSync(outside, "stale", { mode: 0o600 });
    // The sidecar is a symlink pointing outside the store.
    symlinkSync(outside, path.join(dir, "pins.json.integrity"));
    await expect(resetIntegrity()).rejects.toThrow(/symlink/);
  });

  test("readPins throws on format_version mismatch", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "pins.json"), '{"format_version": 99, "servers": {}}', { mode: 0o600 });
    await expect(readPins()).rejects.toThrow(/format_version mismatch/);
  });

  // Fix 6: the integrity sidecar proves bytes, not shape. A structurally
  // invalid (but JSON-valid) pins.json must be rejected with a descriptive
  // error that is NOT a PinsIntegrityError, so the user knows it is malformed
  // rather than tampered.
  test("readPins rejects a structurally-invalid pins.json (Zod), not as a PinsIntegrityError", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // servers is an array, not a record → shape mismatch.
    writeFileSync(path.join(dir, "pins.json"), '{"format_version": 1, "servers": []}', {
      mode: 0o600,
    });
    await expect(readPins()).rejects.toThrow(/invalid structure/);
    await expect(readPins()).rejects.not.toBeInstanceOf(PinsIntegrityError);
  });

  test("readPins rejects a pin entry missing required fields (Zod)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // Entry lacks previous_hashes / captured_at / captured_via / version.
    writeFileSync(
      path.join(dir, "pins.json"),
      '{"format_version": 1, "servers": {"fs": {"read": {"current_hash": "sha256:x"}}}}',
      { mode: 0o600 },
    );
    await expect(readPins()).rejects.toThrow(/invalid structure/);
  });

  test("readPins rejects non-JSON content with a clear (non-integrity) error", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(path.join(dir, "pins.json"), "not json at all", { mode: 0o600 });
    await expect(readPins()).rejects.toThrow(/not valid JSON/);
  });

  // Fix 5: writePins must refuse to write through a symlinked target so a
  // pre-placed symlink cannot redirect the write onto an attacker-chosen path.
  test("writePins refuses to write through a symlinked pins.json", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const outside = path.join(tmpHome, "outside-target");
    writeFileSync(outside, "{}", { mode: 0o600 });
    // pins.json is a symlink pointing outside the store.
    symlinkSync(outside, path.join(dir, "pins.json"));
    await expect(writePins(emptyPinsFile())).rejects.toThrow(/symlink/);
  });

  // H4: field_hashes is backward-compatible (optional). A pre-H4 pins.json
  // (entries without field_hashes) must still validate + round-trip.
  test("pins.json with entries lacking field_hashes round-trips (backward-compat)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(
      path.join(dir, "pins.json"),
      JSON.stringify({
        format_version: PINS_FORMAT_VERSION,
        servers: {
          fs: {
            read: {
              current_hash: "sha256:" + "a".repeat(64),
              previous_hashes: [],
              captured_at: "2026-05-17T00:00:00Z",
              captured_via: "install",
              signature_list_version: "v0.5.0",
            },
          },
        },
      }),
      { mode: 0o600 },
    );
    const pins = await readPins();
    expect(pins.servers.fs?.read?.current_hash).toBe("sha256:" + "a".repeat(64));
    expect(pins.servers.fs?.read?.field_hashes).toBeUndefined();
  });

  // H4: a present-but-malformed field_hashes (non-object, or prototype-pollution
  // shaped) must FAIL CLOSED in the schema, not slip through as a valid pin.
  test("rejects a non-object field_hashes (fails closed)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(
      path.join(dir, "pins.json"),
      '{"format_version": 1, "servers": {"fs": {"read": {"current_hash": "sha256:x", ' +
        '"previous_hashes": [], "captured_at": "x", "captured_via": "install", ' +
        '"signature_list_version": "v", "field_hashes": "not-an-object"}}}}',
      { mode: 0o600 },
    );
    await expect(readPins()).rejects.toThrow(/invalid structure/);
  });

  test("rejects a __proto__-shaped field_hashes (fails closed)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // field_hashes is missing the required string fields (description/schema/
    // annotations) — a {"__proto__":{}}-shaped object does not satisfy the schema.
    writeFileSync(
      path.join(dir, "pins.json"),
      '{"format_version": 1, "servers": {"fs": {"read": {"current_hash": "sha256:x", ' +
        '"previous_hashes": [], "captured_at": "x", "captured_via": "install", ' +
        '"signature_list_version": "v", "field_hashes": {"__proto__": {}}}}}}',
      { mode: 0o600 },
    );
    await expect(readPins()).rejects.toThrow(/invalid structure/);
  });

  // H5: `handshakes` is additive + optional (no format bump). A pre-H5 pins.json
  // (no `handshakes` key) must still validate + round-trip.
  test("pre-H5 pins.json with no handshakes key round-trips (backward-compat)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(
      path.join(dir, "pins.json"),
      JSON.stringify({
        format_version: PINS_FORMAT_VERSION,
        servers: { fs: {} },
      }),
      { mode: 0o600 },
    );
    const pins = await readPins();
    expect(pins.handshakes).toBeUndefined();
    // And a fresh write of a handshakes-bearing file round-trips.
    const fields = handshakeFieldHashesOf({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    const withHandshake = upsertHandshakePin(pins, "fs", {
      current_hash: hashHandshake(fields),
      previous_hashes: [],
      captured_at: "2026-06-14T00:00:00Z",
      captured_via: "first-session",
      signature_list_version: "v0.5.0",
      field_hashes: fields,
      capability_keys: ["tools"],
    });
    await writePins(withHandshake);
    const back = await readPins();
    expect(back.handshakes?.fs?.capability_keys).toEqual(["tools"]);
  });

  // H5: a present-but-malformed handshakes entry must FAIL CLOSED in the schema.
  test("rejects a malformed handshakes entry (fails closed)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(
      path.join(dir, "pins.json"),
      '{"format_version": 1, "servers": {}, "handshakes": {"fs": {"current_hash": "sha256:x"}}}',
      { mode: 0o600 },
    );
    await expect(readPins()).rejects.toThrow(/invalid structure/);
    await expect(readPins()).rejects.not.toBeInstanceOf(PinsIntegrityError);
  });
});

// Issue #19: the unkeyed SHA-256 sidecars must be documented as integrity
// (tamper-evidence), NOT authenticity vs a same-user/postinstall attacker, who
// can recompute the sidecar to match. These tests pin the honest wording in the
// source comments so the overclaim cannot silently return. Docs-only contract.
describe("issue #19 — integrity sidecars relabeled integrity-not-authenticity", () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const readSrc = (rel: string) => readFileSync(path.join(here, rel), "utf-8");

  test("pins.ts states integrity-not-authenticity and references issue #19", () => {
    const src = readSrc("../pins.ts");
    expect(src).toMatch(/issue #19/i);
    expect(src).toMatch(/UNKEYED SHA-256/);
    expect(src).toMatch(/NOT AUTHENTICITY|not a keyed MAC/);
    // The pre-fix comment claimed it "lets us detect tampering by another
    // local process" with no caveat — that overclaim must be gone.
    expect(src).not.toMatch(/lets us detect tampering\s*\n?\s*\* by another local process\./);
  });

  test("policy.ts states integrity-not-authenticity and references issue #19", () => {
    const src = readSrc("../policy.ts");
    expect(src).toMatch(/issue #19/i);
    expect(src).toMatch(/UNKEYED SHA-256/);
    expect(src).toMatch(/NOT\s*\n?\s*\/\/\s*AUTHENTICITY|not authenticity/i);
    // The pre-fix comment claimed a malicious postinstall "silently disables
    // guard signatures" with no caveat that it can also rewrite the sidecar.
    expect(src).not.toMatch(/script that mutates this file silently disables guard/);
  });
});
