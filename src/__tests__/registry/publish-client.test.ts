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

  it("rejects an over-cap publish response rather than fully buffering it (security #21)", async () => {
    // A stream that would emit > 10 MB. readCappedBody must abort partway and
    // throw — we assert it never reads to completion (cancel is called).
    const CHUNK = new Uint8Array(2 * 1024 * 1024); // 2 MB per pull
    let pulls = 0;
    const cancel = vi.fn().mockResolvedValue(undefined);
    const reader = {
      read: vi.fn().mockImplementation(async () => {
        pulls += 1;
        return { done: false, value: CHUNK }; // never "done" — would be unbounded
      }),
      cancel,
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => null },
      body: { getReader: () => reader },
      // json() must NOT be used for a streamable body; fail loudly if it is.
      json: async () => {
        throw new Error("response.json() should not be called for a streamable over-cap body");
      },
    }));

    await expect(submitToRegistry(MANIFEST, TOKEN, REGISTRY_URL)).rejects.toThrow(/cap/i);
    // Aborted partway: 10 MB cap / 2 MB chunks ⇒ ~6 pulls, far fewer than ∞.
    expect(pulls).toBeLessThan(10);
    expect(cancel).toHaveBeenCalled();
  });
});

describe("validateRegistryUrl (security #17 — token-exfil guard)", () => {
  it("accepts a public https URL", () => {
    expect(() => validateRegistryUrl("https://registry.modelcontextprotocol.io")).not.toThrow();
  });

  it("rejects http (no auth token over plaintext)", () => {
    expect(() => validateRegistryUrl("http://registry.example.com")).toThrow(/https/);
  });

  it("rejects loopback and private/internal hosts (incl. IPv4-mapped IPv6, ULA, integer forms)", () => {
    for (const u of [
      "https://localhost",
      "https://127.0.0.1",
      "https://10.0.0.5",
      "https://192.168.1.1",
      "https://172.16.0.1",
      "https://169.254.1.1",
      "https://[::1]",
      "https://[::ffff:127.0.0.1]", // IPv4-mapped IPv6 loopback (review finding)
      "https://[::ffff:10.0.0.1]",
      "https://[fc00::1]", // IPv6 unique-local
      "https://[fd12::1]",
      "https://[fdff::1]", // top of unique-local fc00::/7
      "https://[fe80::1]", // IPv6 link-local
      // fe80::/10 link-local addresses that do NOT begin literally with "fe80"
      // and previously bypassed the startsWith("fe80") guard (review finding).
      "https://[fea0::1]",
      "https://[feb0::1]",
      "https://[febf::1]", // top of link-local fe80::/10
      "https://2130706433", // integer form of 127.0.0.1 (Node normalizes → caught)
    ]) {
      expect(() => validateRegistryUrl(u), u).toThrow(/non-public/);
    }
  });

  it("allows a normal public IPv6 address (e.g. 2001:db8::/fec0:: just outside link-local)", () => {
    // 2001:db8::1 is documentation/public-range and must NOT be blocked.
    expect(() => validateRegistryUrl("https://[2001:db8::1]")).not.toThrow();
    // fec0::1 is just past the link-local ceiling (febf) — not link-local/ULA.
    expect(() => validateRegistryUrl("https://[fec0::1]")).not.toThrow();
  });

  it("rejects a registry URL with embedded credentials", () => {
    expect(() => validateRegistryUrl("https://user:pass@registry.example.com")).toThrow(
      /credentials/
    );
    expect(() => validateRegistryUrl("https://attacker@registry.example.com")).toThrow(
      /credentials/
    );
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
