/**
 * Tests for src/store/keychain.ts — written FIRST per TDD (Red → Green).
 *
 * Uses crypto.subtle machine-keyed encryption (no native deps).
 * Strategy: mock the machine-id derivation so tests are deterministic.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("keychain store", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("stores and retrieves a secret by server+key", async () => {
    const { setSecret, getSecret } = await import("../../store/keychain.js");
    await setSecret("my-server", "API_KEY", "sk-test-123");
    const result = await getSecret("my-server", "API_KEY");
    expect(result).toBe("sk-test-123");
  });

  it("returns null for a key that was never set", async () => {
    const { getSecret } = await import("../../store/keychain.js");
    const result = await getSecret("my-server", "NONEXISTENT_KEY");
    expect(result).toBeNull();
  });

  it("overwrites an existing secret when set is called again", async () => {
    const { setSecret, getSecret } = await import("../../store/keychain.js");
    await setSecret("my-server", "API_KEY", "old-value");
    await setSecret("my-server", "API_KEY", "new-value");
    expect(await getSecret("my-server", "API_KEY")).toBe("new-value");
  });

  it("deletes a secret, returns true, and reads null afterwards", async () => {
    const { setSecret, getSecret, deleteSecret } = await import("../../store/keychain.js");
    await setSecret("my-server", "API_KEY", "to-be-deleted");
    expect(await deleteSecret("my-server", "API_KEY")).toBe(true);
    expect(await getSecret("my-server", "API_KEY")).toBeNull();
  });

  it("deleteSecret is a no-op for nonexistent keys (returns false, does not throw)", async () => {
    const { deleteSecret } = await import("../../store/keychain.js");
    await expect(deleteSecret("my-server", "GHOST_KEY")).resolves.toBe(false);
  });

  it("lists secret keys without revealing values", async () => {
    const { setSecret, listSecretKeys } = await import("../../store/keychain.js");
    await setSecret("my-server", "API_KEY", "v1");
    await setSecret("my-server", "TOKEN", "v2");
    const keys = await listSecretKeys("my-server");
    expect(keys).toContain("API_KEY");
    expect(keys).toContain("TOKEN");
    expect(keys.length).toBe(2);
  });

  it("isolates secrets per server name", async () => {
    const { setSecret, getSecret } = await import("../../store/keychain.js");
    await setSecret("server-a", "KEY", "value-a");
    await setSecret("server-b", "KEY", "value-b");
    expect(await getSecret("server-a", "KEY")).toBe("value-a");
    expect(await getSecret("server-b", "KEY")).toBe("value-b");
  });

  it("produces a placeholder string for use in config files", async () => {
    const { toPlaceholder } = await import("../../store/keychain.js");
    const ph = toPlaceholder("my-server", "API_KEY");
    expect(ph).toBe("mcpm:keychain:my-server/API_KEY");
  });

  it("parses a placeholder string back to server+key", async () => {
    const { parsePlaceholder } = await import("../../store/keychain.js");
    const result = parsePlaceholder("mcpm:keychain:my-server/API_KEY");
    expect(result).toEqual({ server: "my-server", key: "API_KEY" });
  });

  it("returns null for non-placeholder strings", async () => {
    const { parsePlaceholder } = await import("../../store/keychain.js");
    expect(parsePlaceholder("plain-api-key")).toBeNull();
    expect(parsePlaceholder("")).toBeNull();
  });
});
