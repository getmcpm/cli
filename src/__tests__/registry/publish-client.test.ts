/**
 * Tests for src/registry/publish-client.ts
 * Covers: successful POST, non-ok response throws RegistryError,
 * network failure throws NetworkError, body.url fallback.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { submitToRegistry, validateRegistryUrl } from "../../registry/publish-client.js";
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

  it("passes redirect:'manual' so a 3xx can't carry the token to the redirect target", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ url: "https://registry.example.com/servers/x" }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ redirect: "manual" })
    );
  });
});

describe("validateRegistryUrl (security #17 — token-exfil guard)", () => {
  it("accepts a public https URL", () => {
    expect(() => validateRegistryUrl("https://registry.modelcontextprotocol.io")).not.toThrow();
  });

  it("rejects http (no auth token over plaintext)", () => {
    expect(() => validateRegistryUrl("http://registry.example.com")).toThrow(/https/);
  });

  it("rejects loopback and private/internal hosts", () => {
    for (const u of [
      "https://localhost",
      "https://127.0.0.1",
      "https://10.0.0.5",
      "https://192.168.1.1",
      "https://172.16.0.1",
      "https://169.254.1.1",
      "https://[::1]",
    ]) {
      expect(() => validateRegistryUrl(u), u).toThrow(/non-public/);
    }
  });

  it("rejects a malformed URL", () => {
    expect(() => validateRegistryUrl("not a url")).toThrow(/Invalid registry URL/);
  });

  it("submitToRegistry never calls fetch for an unsafe URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      submitToRegistry(MANIFEST, TOKEN, "http://evil.example.com")
    ).rejects.toThrow(/https/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
