/**
 * Tests for src/registry/publish-client.ts
 * Covers: successful POST, non-ok response throws RegistryError,
 * network failure throws NetworkError, body.url fallback.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { submitToRegistry } from "../../registry/publish-client.js";
import { NetworkError, RegistryError } from "../../registry/errors.js";

const MANIFEST = {
  name: "io.github.test/my-server",
  description: "A test server",
  tags: [],
  package: { registryType: "npm" as const, identifier: "@test/my-server" },
};

const REGISTRY_URL = "https://registry.example.com";
const TOKEN = "ghp_test_token";

describe("submitToRegistry", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns the url from the response body on success", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ url: "https://registry.example.com/servers/my-server" }),
    }));

    const result = await submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL);
    expect(result.url).toBe("https://registry.example.com/servers/my-server");
  });

  it("falls back to constructed url when body.url is missing", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    }));

    const result = await submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL);
    expect(result.url).toContain("io.github.test%2Fmy-server");
  });

  it("throws RegistryError on non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    }));

    await expect(submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL)).rejects.toThrow(RegistryError);
  });

  it("throws NetworkError when fetch rejects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network failure")));

    await expect(submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL)).rejects.toThrow(NetworkError);
  });
});
