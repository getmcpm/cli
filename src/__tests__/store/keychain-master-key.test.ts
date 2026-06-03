/**
 * Tests for the OS-keychain master-key scheme in src/store/keychain.ts
 * (security #15): new secrets are AES-GCM-encrypted with a key derived (HKDF)
 * from a random master key held in the OS keychain, tagged "k1:". Legacy
 * machine-scheme entries ("salt:iv:ct") stay decryptable, and `migrateToKeychain`
 * upgrades them.
 *
 * Isolation:
 *   - `store/os-keychain.ts` is mocked so no real OS keychain is touched and the
 *     test controls availability + the stored master key.
 *   - `os.homedir()` is redirected to a temp dir so the store file is written
 *     under the system temp dir, never the developer's real ~/.mcpm.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import os from "os";
import path from "node:path";
import { readFile, rm } from "node:fs/promises";

const osk = vi.hoisted(() => ({ available: true, stored: null as Buffer | null }));

vi.mock("../../store/os-keychain.js", () => ({
  isSupportedPlatform: () => osk.available,
  getStoredKey: async () => (osk.stored ? Buffer.from(osk.stored) : null),
  storeKey: async (k: Buffer) => {
    osk.stored = Buffer.from(k);
    return true;
  },
}));

vi.mock("os", async (importActual) => {
  const actual = await importActual<typeof import("os")>();
  const pathm = await import("node:path");
  const HOME = pathm.join(actual.tmpdir(), "mcpm-kc-mk-test-home");
  return { ...actual, default: { ...actual, homedir: () => HOME }, homedir: () => HOME };
});

function storeFile(): string {
  return path.join(os.homedir(), ".mcpm", "secrets.enc.json");
}

async function rawEntry(sk: string): Promise<string | undefined> {
  try {
    const json = JSON.parse(await readFile(storeFile(), "utf8")) as Record<string, string>;
    return json[sk];
  } catch {
    return undefined;
  }
}

beforeEach(async () => {
  vi.resetModules();
  osk.available = true;
  osk.stored = null;
  await rm(storeFile(), { force: true });
});

describe("keychain master-key scheme (security #15)", () => {
  it("encrypts new secrets under the keychain scheme (k1) and round-trips", async () => {
    const kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "API_KEY", "sk-live-123");
    expect(await kc.getSecret("srv", "API_KEY")).toBe("sk-live-123");
    expect((await rawEntry("srv/API_KEY"))?.startsWith("k1:")).toBe(true);
    expect(osk.stored).not.toBeNull(); // a master key was generated + persisted
  });

  it("falls back to the legacy machine scheme (unprefixed) when no OS keychain", async () => {
    osk.available = false;
    const kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "TOKEN", "v");
    expect(await kc.getSecret("srv", "TOKEN")).toBe("v");
    const entry = await rawEntry("srv/TOKEN");
    expect(entry?.startsWith("k1:")).toBe(false);
    expect(entry?.split(":").length).toBe(3);
  });

  it("still decrypts legacy machine-scheme entries after the keychain is enabled", async () => {
    osk.available = false;
    let kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "OLD", "legacy-value");

    osk.available = true; // keychain now available
    osk.stored = null;
    vi.resetModules();
    kc = await import("../../store/keychain.js");
    expect(await kc.getSecret("srv", "OLD")).toBe("legacy-value");
  });

  it("migrateToKeychain re-encrypts every legacy entry under the keychain key", async () => {
    osk.available = false;
    let kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "A", "aaa");
    await kc.setSecret("srv", "B", "bbb");

    osk.available = true;
    osk.stored = null;
    vi.resetModules();
    kc = await import("../../store/keychain.js");

    const res = await kc.migrateToKeychain();
    expect(res).toMatchObject({ usingKeychain: true, migrated: 2, failed: 0, total: 2 });
    expect((await rawEntry("srv/A"))?.startsWith("k1:")).toBe(true);
    expect((await rawEntry("srv/B"))?.startsWith("k1:")).toBe(true);
    expect(await kc.getSecret("srv", "A")).toBe("aaa");
    expect(await kc.getSecret("srv", "B")).toBe("bbb");
  });

  it("migrateToKeychain is a no-op when no OS keychain is available", async () => {
    osk.available = false;
    const kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "A", "aaa");
    const res = await kc.migrateToKeychain();
    expect(res).toMatchObject({ usingKeychain: false, migrated: 0 });
    expect((await rawEntry("srv/A"))?.split(":").length).toBe(3); // left untouched
  });

  it("throws a clear error decrypting a keychain entry when the master key is gone", async () => {
    osk.available = true;
    let kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "K", "secret");
    expect((await rawEntry("srv/K"))?.startsWith("k1:")).toBe(true);

    osk.stored = null; // master key removed / copied to another machine
    vi.resetModules();
    kc = await import("../../store/keychain.js");
    await expect(kc.getSecret("srv", "K")).rejects.toThrow(/OS keychain master key/i);
  });

  it("activeSecretBackend reports os-keychain after a keychain-scheme set", async () => {
    osk.available = true;
    const kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "K", "secret");
    expect(await kc.activeSecretBackend()).toBe("os-keychain");
  });

  it("activeSecretBackend reports machine-key when no OS keychain is available", async () => {
    osk.available = false;
    const kc = await import("../../store/keychain.js");
    await kc.setSecret("srv", "K", "secret");
    expect(await kc.activeSecretBackend()).toBe("machine-key");
  });
});
