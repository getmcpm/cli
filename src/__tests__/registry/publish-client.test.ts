/**
 * Tests for src/registry/publish-client.ts
 *
 * Covers: the three live paths (POST /v0.1/publish, /v0.1/auth/github-at,
 * /v0.1/auth/github-oidc), the Actions OIDC token mint, audience derivation,
 * and the token-routing invariant — a GitHub token must reach only
 * /v0.1/auth/github-at, and /v0.1/publish must receive only the exchanged
 * registry token. Each is written so that reverting the fix (e.g. posting to
 * /v0.1/servers again, or sending the GitHub token to /v0.1/publish) fails it.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  submitToRegistry,
  validateRegistryUrl,
  exchangeGitHubToken,
  exchangeGitHubOidcToken,
  fetchActionsOidcToken,
  audienceFromRegistryUrl,
} from "../../registry/publish-client.js";
import { NetworkError, RegistryError } from "../../registry/errors.js";
import type { ServerJson } from "../../commands/publish/manifest.js";

const SERVER_JSON: ServerJson = {
  $schema: "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  name: "io.github.test/my-server",
  description: "A test server",
  version: "1.0.0",
  packages: [
    {
      registryType: "npm",
      identifier: "@test/my-server",
      version: "1.0.0",
      transport: { type: "stdio" },
    },
  ],
};

const REGISTRY_URL = "https://registry.example.com";
const REGISTRY_TOKEN = "registry-jwt-token";

describe("submitToRegistry", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("POSTs to /v0.1/publish, not the old (nonexistent) /v0.1/servers", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);
    await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL);
    expect(fetchMock).toHaveBeenCalledWith(
      `${REGISTRY_URL}/v0.1/publish`,
      expect.anything()
    );
  });

  it("returns the url from the response body on success", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ url: "https://registry.example.com/servers/my-server" }),
    }));

    const result = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL);
    expect(result.url).toBe("https://registry.example.com/servers/my-server");
  });

  it("falls back to a constructed url when body.url is missing (the real ServerResponse shape has none)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({}),
    }));

    const result = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL);
    expect(result.url).toContain("io.github.test%2Fmy-server");
  });

  it("throws RegistryError on non-ok response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
    }));

    await expect(submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL)).rejects.toThrow(RegistryError);
  });

  it("surfaces detail + errors[].message from a problem+json 422 body, not just the bare status", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      headers: { get: () => null },
      json: async () => ({
        title: "Unprocessable Entity",
        status: 422,
        detail: "validation failed",
        errors: [{ message: "expected required property $schema to be present", location: "body" }],
      }),
    }));

    const err = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL).catch((e: Error) => e);
    expect((err as Error).message).toContain("validation failed");
    expect((err as Error).message).toContain("expected required property $schema to be present");
  });

  it("falls back to the bare status when the error body isn't readable (e.g. a mock with no .json())", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const err = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL).catch((e: Error) => e);
    expect((err as Error).message).toBe("Registry API returned 500");
  });

  // #216 review, MED 3: detail/title/errors[].message are registry-controlled
  // and land in a thrown Error's .message, which publish/index.ts prints
  // straight to the terminal — an ANSI/OSC/control-char escape sequence in
  // any of them must not reach stdout/stderr unsanitized.
  it("strips terminal escape sequences from a 422 body's detail/errors before they reach the thrown message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      headers: { get: () => null },
      json: async () => ({
        title: "Unprocessable Entity",
        status: 422,
        detail: "[2J]0;pwnedvalidation failed",
        errors: [{ message: "]0;evilbad field", location: "body" }],
      }),
    }));

    const err = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL).catch((e: Error) => e);
    const message = (err as Error).message;
    expect(message).not.toContain("");
    expect(message).not.toContain("");
    expect(message).toContain("validation failed");
    expect(message).toContain("bad field");
  });

  // #216 review, LOW 8: the registry echoes the whole submitted request body
  // back in errors[].value on a 422 — that must never be interpolated into
  // the thrown message (it can carry arbitrary manifest data).
  it("never includes errors[].value in the thrown message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      headers: { get: () => null },
      json: async () => ({
        title: "Unprocessable Entity",
        status: 422,
        errors: [{ message: "invalid", location: "body.name", value: { github_token: "SENTINEL" } }],
      }),
    }));

    const err = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL).catch((e: Error) => e);
    expect((err as Error).message).not.toContain("SENTINEL");
  });

  it("throws NetworkError when fetch rejects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("Network failure")));

    await expect(submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL)).rejects.toThrow(NetworkError);
  });

  it("passes redirect:'manual' so a 3xx can't carry the token to the redirect target", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ url: "https://registry.example.com/servers/x" }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ redirect: "manual" })
    );
  });

  it("reads a streamed (body.getReader) success response within the cap and parses it (security #21)", async () => {
    // Exercises the production ReadableStream path on success: a small valid
    // JSON payload delivered in two chunks → readCappedStream concats → JSON.parse.
    const payload = JSON.stringify({ url: "https://registry.example.com/servers/streamed" });
    const bytes = new TextEncoder().encode(payload);
    const mid = Math.ceil(bytes.length / 2);
    const reads = [
      { done: false, value: bytes.subarray(0, mid) },
      { done: false, value: bytes.subarray(mid) },
      { done: true, value: undefined as Uint8Array | undefined },
    ];
    const reader = {
      read: vi.fn().mockImplementation(async () => reads.shift()),
      cancel: vi.fn().mockResolvedValue(undefined),
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => null },
      body: { getReader: () => reader },
      // json() must NOT be used when a streamable body is present.
      json: async () => {
        throw new Error("response.json() should not be called for a streamable body");
      },
    }));

    const result = await submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL);
    expect(result.url).toBe("https://registry.example.com/servers/streamed");
    expect(reader.read).toHaveBeenCalled();
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

    await expect(submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, REGISTRY_URL)).rejects.toThrow(/cap/i);
    // Aborted partway: 10 MB cap / 2 MB chunks ⇒ ~6 pulls, far fewer than ∞.
    expect(pulls).toBeLessThan(10);
    expect(cancel).toHaveBeenCalled();
  });
});

describe("exchangeGitHubToken", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("POSTs {github_token} to /v0.1/auth/github-at", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ registry_token: "rt-123", expires_at: 999 }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await exchangeGitHubToken(REGISTRY_URL, "ghp_secret");
    expect(result).toEqual({ registryToken: "rt-123", expiresAt: 999 });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${REGISTRY_URL}/v0.1/auth/github-at`);
    expect(JSON.parse(init.body as string)).toEqual({ github_token: "ghp_secret" });
  });

  it("does not send the GitHub token as a Bearer header (the endpoint takes it in the body only)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ registry_token: "rt", expires_at: 1 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await exchangeGitHubToken(REGISTRY_URL, "ghp_secret");
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it("surfaces the registry's 401 detail on a bad token (live shape: {title,status,detail})", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: { get: () => null },
      json: async () => ({ title: "Unauthorized", status: 401, detail: "Token exchange failed" }),
    }));
    const err = await exchangeGitHubToken(REGISTRY_URL, "bad").catch((e: Error) => e);
    expect(err).toBeInstanceOf(RegistryError);
    expect((err as Error).message).toContain("Token exchange failed");
  });

  it("never calls fetch for an unsafe registry URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(exchangeGitHubToken("http://evil.example.com", "t")).rejects.toThrow(/https/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("exchangeGitHubOidcToken", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("POSTs {oidc_token} to /v0.1/auth/github-oidc", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ registry_token: "rt-oidc", expires_at: 42 }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await exchangeGitHubOidcToken(REGISTRY_URL, "eyJ.oidc.jwt");
    expect(result).toEqual({ registryToken: "rt-oidc", expiresAt: 42 });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${REGISTRY_URL}/v0.1/auth/github-oidc`);
    expect(JSON.parse(init.body as string)).toEqual({ oidc_token: "eyJ.oidc.jwt" });
  });

  // #216 review, MED 1: exchangeGitHubOidcToken had no test pinning that it
  // calls validateRegistryUrl before fetch — the sibling exchangeGitHubToken
  // describe block above has this test, exchangeGitHubOidcToken did not, and
  // deleting its validateRegistryUrl(registryUrl) call left the full suite
  // green.
  it("never calls fetch for an unsafe registry URL", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(exchangeGitHubOidcToken("http://evil.example.com", "t")).rejects.toThrow(/https/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// #216 review, MED 2: the reference implementation
// (cmd/publisher/auth/github-oidc.go:182) uses Go's `u.Host`, which KEEPS the
// port; this previously used `parsed.hostname`, which drops it — a
// `--registry https://example.com:8443` minted a token whose audience
// silently dropped ":8443", failing that registry's issuer check.
describe("audienceFromRegistryUrl (parity with cmd/publisher/auth/github-oidc.go's u.Host)", () => {
  it("derives scheme + lowercased host, matching the official publisher's audienceFromRegistryURL", () => {
    expect(audienceFromRegistryUrl("https://registry.modelcontextprotocol.io")).toBe(
      "https://registry.modelcontextprotocol.io"
    );
  });

  it("lowercases a mixed-case host", () => {
    expect(audienceFromRegistryUrl("https://Registry.ModelContextProtocol.IO")).toBe(
      "https://registry.modelcontextprotocol.io"
    );
  });

  it("drops path/query — audience is scheme+host only", () => {
    expect(audienceFromRegistryUrl("https://registry.example.com/v0.1")).toBe(
      "https://registry.example.com"
    );
  });

  it("keeps a non-default port (u.Host includes it; parsed.hostname would drop it)", () => {
    expect(audienceFromRegistryUrl("https://EXAMPLE.com:8443")).toBe("https://example.com:8443");
  });
});

describe("fetchActionsOidcToken", () => {
  beforeEach(() => vi.restoreAllMocks());

  const ENV = {
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://pipelines.actions.githubusercontent.com/token?api-version=2.0",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "actions-request-token",
  };

  it("GETs the Actions token endpoint with the audience query param and Bearer request token", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ value: "the-oidc-jwt" }) });
    vi.stubGlobal("fetch", fetchMock);

    const token = await fetchActionsOidcToken("https://registry.modelcontextprotocol.io", ENV);
    expect(token).toBe("the-oidc-jwt");

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      `${ENV.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${encodeURIComponent("https://registry.modelcontextprotocol.io")}`
    );
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${ENV.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`);
  });

  it("throws a clear id-token:write error when ACTIONS_ID_TOKEN_REQUEST_URL is absent", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      fetchActionsOidcToken("https://registry.modelcontextprotocol.io", {
        ACTIONS_ID_TOKEN_REQUEST_TOKEN: "t",
      })
    ).rejects.toThrow(/id-token: write/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("throws a clear id-token:write error when ACTIONS_ID_TOKEN_REQUEST_TOKEN is absent", async () => {
    await expect(
      fetchActionsOidcToken("https://registry.modelcontextprotocol.io", {
        ACTIONS_ID_TOKEN_REQUEST_URL: "https://pipelines.example/token",
      })
    ).rejects.toThrow(/id-token: write/);
  });

  it("throws when the Actions endpoint responds without a value", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) }));
    await expect(fetchActionsOidcToken("https://registry.modelcontextprotocol.io", ENV)).rejects.toThrow(
      /no value/i
    );
  });
});

describe("token-routing invariant (security)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("a GitHub token passed to exchangeGitHubToken never reaches any URL other than /v0.1/auth/github-at", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ registry_token: "rt", expires_at: 1 }),
    });
    vi.stubGlobal("fetch", fetchMock);
    await exchangeGitHubToken(REGISTRY_URL, "super-secret-gh-token");

    for (const call of fetchMock.mock.calls) {
      const [url, init] = call as [string, RequestInit];
      const serialized = JSON.stringify(init);
      if (serialized.includes("super-secret-gh-token")) {
        expect(url).toBe(`${REGISTRY_URL}/v0.1/auth/github-at`);
      }
    }
  });

  it("submitToRegistry sends the exchanged registry token to /v0.1/publish as a Bearer header, and it alone", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) });
    vi.stubGlobal("fetch", fetchMock);
    await submitToRegistry(SERVER_JSON, "the-registry-jwt", REGISTRY_URL);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${REGISTRY_URL}/v0.1/publish`);
    const headers = init.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer the-registry-jwt");
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
      "https://[2002:7f00:1::]", // 6to4 (2002::/16) embedding 127.0.0.1 (review finding)
      "https://100.64.0.1", // CGNAT 100.64.0.0/10 (RFC 6598, review finding)
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

  it("allows normal public IPv4/IPv6 outside the 6to4 and CGNAT ranges", () => {
    // 93.184.216.34 (example.com) is public; 100.x just outside 100.64/10 is public.
    expect(() => validateRegistryUrl("https://93.184.216.34")).not.toThrow();
    expect(() => validateRegistryUrl("https://100.63.255.255")).not.toThrow();
    expect(() => validateRegistryUrl("https://100.128.0.1")).not.toThrow();
    // 2001:db8::1 (public IPv6) must remain allowed alongside the 6to4 block.
    expect(() => validateRegistryUrl("https://[2001:db8::1]")).not.toThrow();
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
      submitToRegistry(SERVER_JSON, REGISTRY_TOKEN, "http://evil.example.com")
    ).rejects.toThrow(/https/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
