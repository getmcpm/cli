/**
 * Tests for src/registry/ — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - fetchImpl is always a vi.fn() — NO real network calls.
 * - Each describe block covers one logical concern.
 * - All discriminated-union variants of packages[] are tested.
 * - All error branches are tested (404, 500, timeout, bad JSON, Zod failure).
 * - Pagination stop condition is tested.
 * - Immutability: returned objects are frozen/spread copies (spot-checked).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { RegistryClient } from "./client.js";
import {
  RegistryError,
  NetworkError,
  NotFoundError,
  ValidationError,
} from "./errors.js";
import { paginateServers } from "./pagination.js";
import type { SearchResult, ServerEntry, ServerVersion } from "./types.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_SERVER = {
  $schema: "https://example.com/schema",
  name: "io.github.test/server-basic",
  description: "A test server",
  title: "Basic Test Server",
  version: "1.0.0",
  repository: { url: "https://github.com/test/server", source: "github" },
  websiteUrl: "https://example.com",
  icons: [{ src: "https://example.com/icon.png", mimeType: "image/png" }],
  packages: [
    {
      registryType: "npm",
      identifier: "@test/server",
      version: "1.0.0",
      transport: { type: "stdio" },
      environmentVariables: [
        {
          name: "API_KEY",
          description: "Your API key",
          isRequired: true,
          isSecret: true,
        },
      ],
    },
  ],
  remotes: [],
};

const BASE_META = {
  "io.modelcontextprotocol.registry/official": {
    status: "active",
    publishedAt: "2026-02-24T00:07:27.525636Z",
    updatedAt: "2026-02-24T00:07:27.525636Z",
    isLatest: true,
  },
};

function makeServerEntry(overrides: Partial<typeof BASE_SERVER> = {}) {
  return {
    server: { ...BASE_SERVER, ...overrides },
    _meta: BASE_META,
  };
}

function makeSearchResponse(
  servers: ReturnType<typeof makeServerEntry>[],
  nextCursor?: string,
  count?: number
) {
  return {
    servers,
    metadata: {
      ...(nextCursor !== undefined ? { nextCursor } : {}),
      count: count ?? servers.length,
    },
  };
}

function mockFetch(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: vi.fn().mockResolvedValue(body),
  });
}

function mockFetchReject(error: Error) {
  return vi.fn().mockRejectedValue(error);
}

// ---------------------------------------------------------------------------
// RegistryClient — construction
// ---------------------------------------------------------------------------

describe("RegistryClient — construction", () => {
  it("uses default base URL when none provided", () => {
    const client = new RegistryClient();
    expect(client.baseUrl).toBe("https://registry.modelcontextprotocol.io");
  });

  it("accepts a custom base URL", () => {
    const client = new RegistryClient({ baseUrl: "https://custom.example.com" });
    expect(client.baseUrl).toBe("https://custom.example.com");
  });

  it("strips trailing slash from custom base URL", () => {
    const client = new RegistryClient({ baseUrl: "https://custom.example.com/" });
    expect(client.baseUrl).toBe("https://custom.example.com");
  });
});

// ---------------------------------------------------------------------------
// searchServers — happy path
// ---------------------------------------------------------------------------

describe("RegistryClient.searchServers — happy path", () => {
  it("calls the correct URL with search and version=latest", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([makeServerEntry()]));
    const client = new RegistryClient({ fetchImpl });

    await client.searchServers("filesystem");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("/v0.1/servers");
    expect(url).toContain("search=filesystem");
    expect(url).toContain("version=latest");
  });

  it("returns typed SearchResult with servers array", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([makeServerEntry()]));
    const client = new RegistryClient({ fetchImpl });

    const result: SearchResult = await client.searchServers("test");

    expect(result.servers).toHaveLength(1);
    expect(result.servers[0].server.name).toBe("io.github.test/server-basic");
  });

  it("returns empty servers array when no results", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("zzz-no-match");

    expect(result.servers).toHaveLength(0);
    expect(result.metadata.count).toBe(0);
  });

  it("passes limit param when provided", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    await client.searchServers("test", { limit: 20 });

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("limit=20");
  });

  it("passes version param when provided", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    await client.searchServers("test", { version: "1.0.0" });

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("version=1.0.0");
  });

  it("includes nextCursor in metadata when present", async () => {
    const fetchImpl = mockFetch(
      makeSearchResponse([makeServerEntry()], "server-name:1.0.0", 10)
    );
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");

    expect(result.metadata.nextCursor).toBe("server-name:1.0.0");
    expect(result.metadata.count).toBe(10);
  });

  it("returns object with no nextCursor when omitted", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([makeServerEntry()]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");

    expect(result.metadata.nextCursor).toBeUndefined();
  });

  it("URL-encodes special characters in search query", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    await client.searchServers("hello world & more");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("search=hello+world");
  });
});

// ---------------------------------------------------------------------------
// searchServers — package discriminated union variants
// ---------------------------------------------------------------------------

describe("RegistryClient.searchServers — package variants", () => {
  it("parses npm package entries", async () => {
    const entry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@scope/pkg",
          version: "2.0.0",
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const pkg = result.servers[0].server.packages[0];

    expect(pkg.registryType).toBe("npm");
    expect(pkg.identifier).toBe("@scope/pkg");
  });

  it("parses pypi package entries", async () => {
    const entry = makeServerEntry({
      packages: [
        {
          registryType: "pypi",
          identifier: "my-python-server",
          version: "0.1.0",
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const pkg = result.servers[0].server.packages[0];

    expect(pkg.registryType).toBe("pypi");
    expect(pkg.identifier).toBe("my-python-server");
  });

  it("parses oci/docker package entries", async () => {
    const entry = makeServerEntry({
      packages: [
        {
          registryType: "docker",
          identifier: "ghcr.io/test/server:latest",
          version: "latest",
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const pkg = result.servers[0].server.packages[0];

    expect(pkg.registryType).toBe("docker");
    expect(pkg.identifier).toBe("ghcr.io/test/server:latest");
  });

  it("parses server with remotes[] only (no packages)", async () => {
    const entry = makeServerEntry({
      packages: [],
      remotes: [
        {
          type: "streamable-http",
          url: "https://api.example.com/mcp",
          headers: [
            {
              name: "Authorization",
              isRequired: true,
              isSecret: true,
            },
          ],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const server = result.servers[0].server;

    expect(server.packages).toHaveLength(0);
    expect(server.remotes).toHaveLength(1);
    expect(server.remotes![0].type).toBe("streamable-http");
  });

  it("parses server with both packages[] and remotes[]", async () => {
    const entry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/pkg",
          version: "1.0.0",
          transport: { type: "stdio" },
          environmentVariables: [],
        },
      ],
      remotes: [
        {
          type: "sse",
          url: "https://api.example.com/sse",
          headers: [],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const server = result.servers[0].server;

    expect(server.packages).toHaveLength(1);
    expect(server.remotes).toHaveLength(1);
    expect(server.remotes![0].type).toBe("sse");
  });

  it("parses multiple environmentVariables with all fields", async () => {
    const entry = makeServerEntry({
      packages: [
        {
          registryType: "npm",
          identifier: "@test/pkg",
          version: "1.0.0",
          transport: { type: "stdio" },
          environmentVariables: [
            {
              name: "API_KEY",
              description: "API key",
              isRequired: true,
              isSecret: true,
            },
            {
              name: "DEBUG",
              description: "Enable debug mode",
              isRequired: false,
              isSecret: false,
            },
          ],
        },
      ],
    });
    const fetchImpl = mockFetch(makeSearchResponse([entry]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("test");
    const envVars = result.servers[0].server.packages[0].environmentVariables;

    expect(envVars).toHaveLength(2);
    expect(envVars[0].isRequired).toBe(true);
    expect(envVars[0].isSecret).toBe(true);
    expect(envVars[1].isRequired).toBe(false);
    expect(envVars[1].isSecret).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// searchServers — cursor pagination param
// ---------------------------------------------------------------------------

describe("RegistryClient.searchServers — cursor param", () => {
  it("passes cursor param when provided", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    await client.searchServers("test", { cursor: "server-name:1.0.0" });

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("cursor=");
    expect(decodeURIComponent(url)).toContain("cursor=server-name:1.0.0");
  });
});

// ---------------------------------------------------------------------------
// getServer — happy path
// ---------------------------------------------------------------------------

describe("RegistryClient.getServer — happy path", () => {
  it("calls /v0.1/servers/{name} with URL-encoded slash", async () => {
    const fetchImpl = mockFetch({ server: BASE_SERVER, _meta: BASE_META });
    const client = new RegistryClient({ fetchImpl });

    await client.getServer("io.github.test/server-basic");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("/v0.1/servers/io.github.test%2Fserver-basic");
  });

  it("returns a typed ServerEntry", async () => {
    const fetchImpl = mockFetch({ server: BASE_SERVER, _meta: BASE_META });
    const client = new RegistryClient({ fetchImpl });

    const entry: ServerEntry = await client.getServer("io.github.test/server-basic");

    expect(entry.server.name).toBe("io.github.test/server-basic");
    expect(entry.server.version).toBe("1.0.0");
    expect(entry._meta["io.modelcontextprotocol.registry/official"].isLatest).toBe(
      true
    );
  });

  it("appends version query param when provided", async () => {
    const fetchImpl = mockFetch({ server: BASE_SERVER, _meta: BASE_META });
    const client = new RegistryClient({ fetchImpl });

    await client.getServer("io.github.test/server-basic", "1.0.0");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain("version=1.0.0");
  });
});

// ---------------------------------------------------------------------------
// getServerVersions — happy path
// ---------------------------------------------------------------------------

describe("RegistryClient.getServerVersions — happy path", () => {
  it("calls /v0.1/servers/{name}/versions", async () => {
    const versionsResponse = {
      versions: [
        { version: "2.0.0", publishedAt: "2026-03-01T00:00:00Z" },
        { version: "1.0.0", publishedAt: "2026-01-01T00:00:00Z" },
      ],
    };
    const fetchImpl = mockFetch(versionsResponse);
    const client = new RegistryClient({ fetchImpl });

    await client.getServerVersions("io.github.test/server-basic");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    expect(url).toContain(
      "/v0.1/servers/io.github.test%2Fserver-basic/versions"
    );
  });

  it("returns typed ServerVersion array", async () => {
    const versionsResponse = {
      versions: [
        { version: "2.0.0", publishedAt: "2026-03-01T00:00:00Z" },
        { version: "1.0.0", publishedAt: "2026-01-01T00:00:00Z" },
      ],
    };
    const fetchImpl = mockFetch(versionsResponse);
    const client = new RegistryClient({ fetchImpl });

    const versions: ServerVersion[] = await client.getServerVersions(
      "io.github.test/server-basic"
    );

    expect(versions).toHaveLength(2);
    expect(versions[0].version).toBe("2.0.0");
    expect(versions[1].version).toBe("1.0.0");
  });

  it("returns empty array when server has no versions listed", async () => {
    const fetchImpl = mockFetch({ versions: [] });
    const client = new RegistryClient({ fetchImpl });

    const versions = await client.getServerVersions("io.github.test/server-basic");

    expect(versions).toHaveLength(0);
  });

  it("throws ValidationError when versions response has wrong shape", async () => {
    const fetchImpl = mockFetch({ not_versions: "wrong" });
    const client = new RegistryClient({ fetchImpl });

    await expect(
      client.getServerVersions("io.github.test/server-basic")
    ).rejects.toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// Error handling — HTTP error status codes
// ---------------------------------------------------------------------------

describe("RegistryClient — HTTP error handling", () => {
  it("throws NotFoundError on 404", async () => {
    const fetchImpl = mockFetch({ error: "not found" }, 404);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.getServer("no-such/server")).rejects.toThrow(
      NotFoundError
    );
  });

  it("NotFoundError.message contains the server name", async () => {
    const fetchImpl = mockFetch({ error: "not found" }, 404);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.getServer("no-such/server")).rejects.toThrow(
      /no-such\/server/
    );
  });

  it("throws RegistryError on 500", async () => {
    const fetchImpl = mockFetch({ error: "internal error" }, 500);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(RegistryError);
  });

  it("RegistryError.statusCode is populated from HTTP status", async () => {
    const fetchImpl = mockFetch({ error: "internal error" }, 500);
    const client = new RegistryClient({ fetchImpl });

    try {
      await client.searchServers("test");
    } catch (err) {
      expect(err).toBeInstanceOf(RegistryError);
      expect((err as RegistryError).statusCode).toBe(500);
    }
  });

  it("throws RegistryError on 429 rate-limit", async () => {
    const fetchImpl = mockFetch({ error: "rate limited" }, 429);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(RegistryError);
  });

  it("throws RegistryError on unexpected 3xx redirect (non-ok)", async () => {
    const fetchImpl = mockFetch({ error: "moved" }, 301);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(RegistryError);
  });
});

// ---------------------------------------------------------------------------
// Error handling — network / parse failures
// ---------------------------------------------------------------------------

describe("RegistryClient — network and parse error handling", () => {
  it("wraps fetch rejection in NetworkError", async () => {
    const fetchImpl = mockFetchReject(new Error("ECONNREFUSED"));
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(NetworkError);
  });

  it("NetworkError.cause is the original error", async () => {
    const originalError = new Error("ECONNREFUSED");
    const fetchImpl = mockFetchReject(originalError);
    const client = new RegistryClient({ fetchImpl });

    try {
      await client.searchServers("test");
    } catch (err) {
      expect(err).toBeInstanceOf(NetworkError);
      expect((err as NetworkError).cause).toBe(originalError);
    }
  });

  it("wraps AbortError (timeout) in NetworkError", async () => {
    const abortError = new DOMException("The operation was aborted", "AbortError");
    const fetchImpl = mockFetchReject(abortError);
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(NetworkError);
  });

  it("wraps non-Error thrown value (e.g. string) in NetworkError", async () => {
    // Covers the `err instanceof Error ? err : new Error(String(err))` branch
    const fetchImpl = vi.fn().mockRejectedValue("string error value");
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(NetworkError);
  });

  it("uses URL as fallback in NotFoundError when no serverName context", async () => {
    // searchServers does not pass a serverName to get(), so 404 falls back to URL
    const fetchImpl = mockFetch({ error: "not found" }, 404);
    const client = new RegistryClient({ fetchImpl });

    const err = await client.searchServers("test").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NotFoundError);
    // The message should contain the URL, not undefined
    expect((err as NotFoundError).message).toContain("/v0.1/servers");
  });

  it("throws ValidationError on malformed JSON body (json() throws)", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockRejectedValue(new SyntaxError("Unexpected token")),
    });
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(ValidationError);
  });

  it("throws ValidationError on Zod parse failure (wrong shape)", async () => {
    const fetchImpl = mockFetch({ wrong: "shape", missing: "required fields" });
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(ValidationError);
  });

  it("throws ValidationError when servers field is missing", async () => {
    const fetchImpl = mockFetch({ metadata: { count: 0 } });
    const client = new RegistryClient({ fetchImpl });

    await expect(client.searchServers("test")).rejects.toThrow(ValidationError);
  });

  it("throws ValidationError when getServer response missing server field", async () => {
    const fetchImpl = mockFetch({ data: BASE_SERVER });
    const client = new RegistryClient({ fetchImpl });

    await expect(
      client.getServer("io.github.test/server-basic")
    ).rejects.toThrow(ValidationError);
  });
});

// ---------------------------------------------------------------------------
// Error hierarchy
// ---------------------------------------------------------------------------

describe("Error hierarchy", () => {
  it("NotFoundError is a RegistryError", () => {
    const err = new NotFoundError("test/server");
    expect(err).toBeInstanceOf(RegistryError);
  });

  it("NetworkError is a RegistryError", () => {
    const originalErr = new Error("fail");
    const err = new NetworkError("connection failed", originalErr);
    expect(err).toBeInstanceOf(RegistryError);
  });

  it("ValidationError is a RegistryError", () => {
    const err = new ValidationError("bad shape");
    expect(err).toBeInstanceOf(RegistryError);
  });

  it("all error classes have a name property matching class name", () => {
    expect(new RegistryError("x").name).toBe("RegistryError");
    expect(new NotFoundError("x").name).toBe("NotFoundError");
    expect(new NetworkError("x", new Error()).name).toBe("NetworkError");
    expect(new ValidationError("x").name).toBe("ValidationError");
  });
});

// ---------------------------------------------------------------------------
// Timeout handling
// ---------------------------------------------------------------------------

describe("RegistryClient — timeout", () => {
  it("uses AbortController to cancel requests after timeout", async () => {
    let capturedSignal: AbortSignal | undefined;
    const fetchImpl = vi.fn().mockImplementation(
      (_url: string, init?: RequestInit) => {
        capturedSignal = init?.signal;
        return Promise.resolve({
          ok: true,
          status: 200,
          json: vi
            .fn()
            .mockResolvedValue(makeSearchResponse([makeServerEntry()])),
        });
      }
    );
    const client = new RegistryClient({ fetchImpl, timeout: 5000 });

    await client.searchServers("test");

    expect(capturedSignal).toBeDefined();
    expect(capturedSignal).toBeInstanceOf(AbortSignal);
  });
});

// ---------------------------------------------------------------------------
// Immutability — returned objects are not shared references
// ---------------------------------------------------------------------------

describe("RegistryClient — immutability", () => {
  it("returned search result servers array is a new object each call", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([makeServerEntry()]));
    const client = new RegistryClient({ fetchImpl });

    const result1 = await client.searchServers("test");

    fetchImpl.mockResolvedValue({
      ok: true,
      status: 200,
      json: vi
        .fn()
        .mockResolvedValue(makeSearchResponse([makeServerEntry()])),
    });

    const result2 = await client.searchServers("test");

    expect(result1.servers).not.toBe(result2.servers);
  });
});

// ---------------------------------------------------------------------------
// paginateServers — async generator
// ---------------------------------------------------------------------------

describe("paginateServers — async generator", () => {
  it("yields all servers from a single page (no nextCursor)", async () => {
    const fetchImpl = mockFetch(
      makeSearchResponse([makeServerEntry(), makeServerEntry()], undefined, 2)
    );
    const client = new RegistryClient({ fetchImpl });

    const results: ServerEntry[] = [];
    for await (const entry of paginateServers(client, "test")) {
      results.push(entry);
    }

    expect(results).toHaveLength(2);
  });

  it("follows nextCursor across multiple pages", async () => {
    const page1 = makeSearchResponse(
      [makeServerEntry()],
      "cursor-page-2",
      2
    );
    const page2 = makeSearchResponse([makeServerEntry()], undefined, 2);

    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, json: vi.fn().mockResolvedValue(page1) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: vi.fn().mockResolvedValue(page2) });

    const client = new RegistryClient({ fetchImpl });

    const results: ServerEntry[] = [];
    for await (const entry of paginateServers(client, "test")) {
      results.push(entry);
    }

    expect(results).toHaveLength(2);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("stops after three pages even if nextCursor keeps appearing (safety limit)", async () => {
    // Always returns a nextCursor to simulate infinite pagination
    const infinitePage = makeSearchResponse(
      [makeServerEntry()],
      "always-has-next",
      9999
    );
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: vi.fn().mockResolvedValue(infinitePage),
    });

    const client = new RegistryClient({ fetchImpl });

    const results: ServerEntry[] = [];
    for await (const entry of paginateServers(client, "test", { maxPages: 3 })) {
      results.push(entry);
    }

    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(results).toHaveLength(3);
  });

  it("yields zero items on empty response", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    const results: ServerEntry[] = [];
    for await (const entry of paginateServers(client, "zzz")) {
      results.push(entry);
    }

    expect(results).toHaveLength(0);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("propagates RegistryError thrown by client", async () => {
    const fetchImpl = mockFetch({ error: "server error" }, 500);
    const client = new RegistryClient({ fetchImpl });

    async function drain() {
      for await (const _ of paginateServers(client, "test")) {
        // drain
      }
    }

    await expect(drain()).rejects.toThrow(RegistryError);
  });
});

// ---------------------------------------------------------------------------
// Edge cases — boundary values and special input
// ---------------------------------------------------------------------------

describe("RegistryClient — edge cases", () => {
  it("handles empty string search query", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    const result = await client.searchServers("");

    expect(result.servers).toHaveLength(0);
  });

  it("handles server name with multiple slashes (double-encoded)", async () => {
    const fetchImpl = mockFetch({ server: BASE_SERVER, _meta: BASE_META });
    const client = new RegistryClient({ fetchImpl });

    await client.getServer("io.github.org/namespace/server");

    const [url] = fetchImpl.mock.calls[0] as [string, ...unknown[]];
    // The slash in the name should be encoded so it doesn't become a path segment
    expect(url).toContain("%2F");
  });

  it("handles unicode characters in search query", async () => {
    const fetchImpl = mockFetch(makeSearchResponse([]));
    const client = new RegistryClient({ fetchImpl });

    // Should not throw
    await expect(client.searchServers("日本語")).resolves.toBeDefined();
  });

  it("handles server with missing optional fields gracefully", async () => {
    // title, websiteUrl, icons, remotes are optional
    const minimalServer = {
      name: "io.github.test/minimal",
      description: "minimal server",
      version: "0.0.1",
      packages: [],
    };
    const fetchImpl = mockFetch({
      server: minimalServer,
      _meta: BASE_META,
    });
    const client = new RegistryClient({ fetchImpl });

    const entry = await client.getServer("io.github.test/minimal");

    expect(entry.server.name).toBe("io.github.test/minimal");
  });
});
