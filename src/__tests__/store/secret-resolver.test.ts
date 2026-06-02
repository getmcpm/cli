/**
 * Tests for resolveEnvPlaceholders + listAll in src/store/keychain.ts.
 *
 * Written FIRST per TDD (Red → Green). Mocks the store index so encryption
 * round-trips run in-memory, isolated from the real ~/.mcpm directory.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the store index to avoid real filesystem I/O.
vi.mock("../../store/index.js", () => {
  let store: Record<string, unknown> = {};
  return {
    readJson: vi.fn(async (filename: string) => store[filename] ?? null),
    writeJson: vi.fn(async (filename: string, data: unknown) => {
      store[filename] = data;
    }),
    _resetStore: () => {
      store = {};
    },
  };
});

// withStoreLock wraps real proper-lockfile + the real ~/.mcpm lock file; in
// these in-memory unit tests it should just run the callback. Lock/symlink
// behavior is covered by atomic.test.ts against the real filesystem.
vi.mock("../../store/atomic.js", () => ({
  withStoreLock: vi.fn(async (fn: () => Promise<unknown>) => fn()),
}));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const storeModule = (await import("../../store/index.js")) as any;

describe("resolveEnvPlaceholders", () => {
  beforeEach(() => {
    storeModule._resetStore();
    vi.clearAllMocks();
  });

  it("replaces a keychain placeholder with the decrypted secret", async () => {
    const { setSecret, toPlaceholder, resolveEnvPlaceholders } = await import(
      "../../store/keychain.js"
    );
    await setSecret("gh", "TOKEN", "sk-secret");
    const resolved = await resolveEnvPlaceholders({ TOKEN: toPlaceholder("gh", "TOKEN") });
    expect(resolved.TOKEN).toBe("sk-secret");
  });

  it("passes non-placeholder values through unchanged", async () => {
    const { resolveEnvPlaceholders } = await import("../../store/keychain.js");
    const resolved = await resolveEnvPlaceholders({ PATH: "/usr/bin", FOO: "bar" });
    expect(resolved).toEqual({ PATH: "/usr/bin", FOO: "bar" });
  });

  it("drops undefined env values", async () => {
    const { resolveEnvPlaceholders } = await import("../../store/keychain.js");
    const resolved = await resolveEnvPlaceholders({ DEFINED: "x", MISSING: undefined });
    expect(resolved).toEqual({ DEFINED: "x" });
    expect("MISSING" in resolved).toBe(false);
  });

  it("throws a clear, actionable error when a placeholder references a missing secret", async () => {
    const { toPlaceholder, resolveEnvPlaceholders } = await import("../../store/keychain.js");
    await expect(
      resolveEnvPlaceholders({ TOKEN: toPlaceholder("gh", "ABSENT") })
    ).rejects.toThrow(/gh\/ABSENT.*not found/);
  });

  it("resolves a mix of placeholders and plain values", async () => {
    const { setSecret, toPlaceholder, resolveEnvPlaceholders } = await import(
      "../../store/keychain.js"
    );
    await setSecret("db", "PASSWORD", "p@ss");
    const resolved = await resolveEnvPlaceholders({
      DB_PASSWORD: toPlaceholder("db", "PASSWORD"),
      DB_HOST: "localhost",
    });
    expect(resolved).toEqual({ DB_PASSWORD: "p@ss", DB_HOST: "localhost" });
  });

  it("reads the store ONCE as a consistent snapshot for multiple placeholders", async () => {
    // Consistency fix: all placeholders resolve against a single locked read, so
    // a concurrent delete cannot tear the result. Two placeholders ⇒ exactly one
    // readJson(secrets.enc.json), not one read per key.
    const { setSecrets, toPlaceholder, resolveEnvPlaceholders } = await import(
      "../../store/keychain.js"
    );
    await setSecrets("svc", { A: "va", B: "vb" });
    storeModule.readJson.mockClear();

    const resolved = await resolveEnvPlaceholders({
      VA: toPlaceholder("svc", "A"),
      VB: toPlaceholder("svc", "B"),
    });

    expect(resolved).toEqual({ VA: "va", VB: "vb" });
    const secretReads = storeModule.readJson.mock.calls.filter(
      (c: unknown[]) => c[0] === "secrets.enc.json"
    );
    expect(secretReads).toHaveLength(1);
  });

  it("does not read the store or take the lock when there are no placeholders", async () => {
    const { resolveEnvPlaceholders } = await import("../../store/keychain.js");
    const { withStoreLock } = (await import("../../store/atomic.js")) as unknown as {
      withStoreLock: ReturnType<typeof vi.fn>;
    };
    storeModule.readJson.mockClear();
    (withStoreLock as ReturnType<typeof vi.fn>).mockClear();

    const resolved = await resolveEnvPlaceholders({ PATH: "/usr/bin", HOME: "/home/a" });

    expect(resolved).toEqual({ PATH: "/usr/bin", HOME: "/home/a" });
    expect(withStoreLock).not.toHaveBeenCalled();
    expect(storeModule.readJson).not.toHaveBeenCalled();
  });
});

describe("listAll", () => {
  beforeEach(() => {
    storeModule._resetStore();
    vi.clearAllMocks();
  });

  it("groups stored secret keys by server without revealing values", async () => {
    const { setSecret, listAll } = await import("../../store/keychain.js");
    await setSecret("gh", "TOKEN", "v1");
    await setSecret("gh", "OTHER", "v2");
    await setSecret("db", "PASSWORD", "v3");
    const all = await listAll();
    expect(all.gh.sort()).toEqual(["OTHER", "TOKEN"]);
    expect(all.db).toEqual(["PASSWORD"]);
    expect(JSON.stringify(all)).not.toContain("v1");
  });

  it("returns an empty object when no secrets are stored", async () => {
    const { listAll } = await import("../../store/keychain.js");
    expect(await listAll()).toEqual({});
  });
});

describe("deriveKeychainId round-trip", () => {
  beforeEach(() => {
    storeModule._resetStore();
    vi.clearAllMocks();
  });

  it("a slash-containing server name survives derive → placeholder → resolve", async () => {
    const { setSecret, deriveKeychainId, toPlaceholder, resolveEnvPlaceholders } = await import(
      "../../store/keychain.js"
    );
    const id = deriveKeychainId("io.github.owner/repo-mcp");
    await setSecret(id, "TOKEN", "sk-roundtrip");
    const resolved = await resolveEnvPlaceholders({ TOKEN: toPlaceholder(id, "TOKEN") });
    expect(resolved.TOKEN).toBe("sk-roundtrip");
  });
});

describe("applyKeychainSecrets", () => {
  beforeEach(() => {
    storeModule._resetStore();
    vi.clearAllMocks();
  });

  it("keychain mode encrypts secret keys + writes placeholders; non-secrets stay inline", async () => {
    const { applyKeychainSecrets, getSecret, deriveKeychainId, toPlaceholder, setSecrets } =
      await import("../../store/keychain.js");
    const { env, storedCount } = await applyKeychainSecrets({
      serverName: "io.github.owner/repo",
      resolvedEnv: { API_KEY: "sk-1", REGION: "us" },
      isSecret: (k) => k === "API_KEY",
      mode: "keychain",
      setSecrets,
    });
    const id = deriveKeychainId("io.github.owner/repo");
    expect(storedCount).toBe(1);
    expect(env.API_KEY).toBe(toPlaceholder(id, "API_KEY"));
    expect(env.REGION).toBe("us");
    expect(await getSecret(id, "API_KEY")).toBe("sk-1");
    expect(JSON.stringify(env)).not.toContain("sk-1");
  });

  it("plaintext mode returns the input unchanged and stores nothing", async () => {
    const { applyKeychainSecrets } = await import("../../store/keychain.js");
    const setSecrets = vi.fn();
    const { env, storedCount } = await applyKeychainSecrets({
      serverName: "s",
      resolvedEnv: { API_KEY: "sk-1" },
      isSecret: () => true,
      mode: "plaintext",
      setSecrets,
    });
    expect(env).toEqual({ API_KEY: "sk-1" });
    expect(storedCount).toBe(0);
    expect(setSecrets).not.toHaveBeenCalled();
  });

  it("throws in keychain mode without a setSecrets implementation", async () => {
    const { applyKeychainSecrets } = await import("../../store/keychain.js");
    await expect(
      applyKeychainSecrets({
        serverName: "s",
        resolvedEnv: { K: "v" },
        isSecret: () => true,
        mode: "keychain",
      })
    ).rejects.toThrow(/unavailable/i);
  });
});

describe("placeholderEnvKeys", () => {
  it("returns only keys whose value is a keychain placeholder", async () => {
    const { placeholderEnvKeys, toPlaceholder } = await import("../../store/keychain.js");
    const keys = placeholderEnvKeys({
      A: toPlaceholder("s", "A"),
      B: "plain-value",
      C: toPlaceholder("s", "C"),
    });
    expect(keys.sort()).toEqual(["A", "C"]);
  });

  it("returns [] for undefined env or all-plain values", async () => {
    const { placeholderEnvKeys } = await import("../../store/keychain.js");
    expect(placeholderEnvKeys(undefined)).toEqual([]);
    expect(placeholderEnvKeys({ X: "y" })).toEqual([]);
  });
});
