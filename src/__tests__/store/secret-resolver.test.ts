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
