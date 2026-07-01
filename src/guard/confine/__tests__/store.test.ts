import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, symlinkSync, mkdirSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { _resetCachedStorePath } from "../../../store/index.js";
import {
  ConfineIntegrityError,
  loadProfile,
  readConfineStore,
  resetConfineIntegrity,
  withProfile,
  withoutProfile,
  writeConfineStore,
} from "../store.js";
import { emptyConfineStore, type ConfineProfile } from "../profile.js";

let tmpHome: string;
let originalHome: string | undefined;

const profile: ConfineProfile = {
  tier: "standard",
  require_confine: false,
  read_deny: ["/home/u/.ssh"],
  write_allow: ["/tmp"],
  net: "none",
  scratch_dir: "/home/u/.mcpm/sandbox/srv",
  captured_at: "2026-01-01T00:00:00Z",
};

const storeFile = () => path.join(tmpHome, ".mcpm", "guard-confine.yaml");

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-confine-store-"));
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

describe("confine store round-trip", () => {
  test("write then read returns the same store; loadProfile resolves per server", async () => {
    const store = withProfile(emptyConfineStore(), "srv", profile);
    await writeConfineStore(store);

    const read = await readConfineStore();
    expect(read).toEqual(store);
    expect(await loadProfile("srv")).toEqual(profile);
    expect(await loadProfile("absent")).toBeNull();
  });

  test("missing store file reads as empty (nothing enrolled)", async () => {
    expect(await readConfineStore()).toEqual(emptyConfineStore());
    expect(await loadProfile("anything")).toBeNull();
  });
});

describe("confine store fails CLOSED", () => {
  test("integrity mismatch throws ConfineIntegrityError", async () => {
    await writeConfineStore(withProfile(emptyConfineStore(), "srv", profile));
    // Tamper: change the file content so it no longer matches the sidecar.
    appendFileSync(storeFile(), "\n# sneaky edit\n");
    await expect(readConfineStore()).rejects.toBeInstanceOf(ConfineIntegrityError);
  });

  test("invalid structure throws a plain (non-integrity) error", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(storeFile(), "format_version: 1\nservers:\n  srv:\n    tier: bogus\n", { mode: 0o600 });
    await resetConfineIntegrity(); // make the sidecar match so we reach the Zod check
    await expect(readConfineStore()).rejects.toThrow(/invalid structure/);
    await expect(readConfineStore()).rejects.not.toBeInstanceOf(ConfineIntegrityError);
  });

  test("format_version mismatch is rejected (fail-closed, no silent mis-confine)", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeFileSync(storeFile(), "format_version: 999\nservers: {}\n", { mode: 0o600 });
    await resetConfineIntegrity();
    await expect(readConfineStore()).rejects.toThrow(/format_version mismatch/);
  });

  test("refuses to write through a symlinked store file", async () => {
    const dir = path.join(tmpHome, ".mcpm");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const outside = path.join(tmpHome, "outside-confine");
    writeFileSync(outside, "stale", { mode: 0o600 });
    symlinkSync(outside, storeFile());
    await expect(
      writeConfineStore(withProfile(emptyConfineStore(), "srv", profile)),
    ).rejects.toThrow(/symlink/);
  });
});

describe("immutable helpers", () => {
  test("withProfile / withoutProfile do not mutate the input", () => {
    const s0 = emptyConfineStore();
    const s1 = withProfile(s0, "a", profile);
    expect(s0.servers).toEqual({});
    expect(s1.servers.a).toEqual(profile);
    const s2 = withoutProfile(s1, "a");
    expect(s1.servers.a).toEqual(profile); // s1 untouched
    expect(s2.servers.a).toBeUndefined();
  });
});
