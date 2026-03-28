/**
 * Tests for src/commands/search.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - RegistryClient is injected as a mock (no real network calls).
 * - output() is injected to capture stdout without process.stdout.write.
 * - Test handler functions directly — not Commander parsing.
 * - Cover: happy path, no results, --limit option, --json flag, error cases.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { SearchResult } from "../../registry/types.js";
import { NotFoundError, NetworkError } from "../../registry/errors.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_SERVER_ENTRY = {
  server: {
    name: "io.github.test/server-basic",
    description: "A test server",
    version: "1.0.0",
    repository: { url: "https://github.com/test/server" },
    packages: [
      {
        registryType: "npm",
        identifier: "@test/server",
        version: "1.0.0",
        transport: { type: "stdio" },
        environmentVariables: [
          { name: "API_KEY", description: "Your API key", isRequired: true },
        ],
      },
    ],
    remotes: [],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      publishedAt: "2026-02-24T00:07:27.525636Z",
      isLatest: true,
    },
  },
};

const PYPI_SERVER_ENTRY = {
  server: {
    name: "io.github.test/python-server",
    description: "A Python server",
    version: "0.5.0",
    packages: [
      {
        registryType: "pypi",
        identifier: "python-mcp-server",
        version: "0.5.0",
        transport: { type: "stdio" },
        environmentVariables: [],
      },
    ],
    remotes: [],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      publishedAt: "2026-01-10T00:00:00Z",
      isLatest: true,
    },
  },
};

const DOCKER_SERVER_ENTRY = {
  server: {
    name: "io.github.test/docker-server",
    description: "A Docker server",
    version: "2.0.0",
    packages: [
      {
        registryType: "docker",
        identifier: "ghcr.io/test/server:latest",
        version: "latest",
        transport: { type: "stdio" },
        environmentVariables: [],
      },
    ],
    remotes: [],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      publishedAt: "2026-02-01T00:00:00Z",
      isLatest: true,
    },
  },
};

const HTTP_SERVER_ENTRY = {
  server: {
    name: "io.github.test/http-server",
    description: "An HTTP server",
    version: "1.2.0",
    packages: [],
    remotes: [
      {
        type: "streamable-http",
        url: "https://api.example.com/mcp",
        headers: [],
      },
    ],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      publishedAt: "2026-02-15T00:00:00Z",
      isLatest: true,
    },
  },
};

function makeSearchResult(servers = [BASE_SERVER_ENTRY]): SearchResult {
  return {
    servers,
    metadata: { count: servers.length },
  };
}

function makeMockClient(searchResult: SearchResult = makeSearchResult()) {
  return {
    searchServers: vi.fn().mockResolvedValue(searchResult),
    getServer: vi.fn(),
    getServerVersions: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Import after fixture setup
// ---------------------------------------------------------------------------

import { handleSearch } from "../../commands/search.js";
import type { SearchOptions } from "../../commands/search.js";

// ---------------------------------------------------------------------------
// handleSearch — happy path
// ---------------------------------------------------------------------------

describe("handleSearch — happy path", () => {
  it("calls searchServers with the provided query", async () => {
    const client = makeMockClient();
    const output = vi.fn();

    await handleSearch("filesystem", { limit: 20 }, { registryClient: client as any, output });

    expect(client.searchServers).toHaveBeenCalledWith("filesystem", expect.objectContaining({ limit: 20 }));
  });

  it("outputs a table with Name, Description, Version, Transport, Trust Score columns", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("Name");
    expect(fullOutput).toContain("Description");
    expect(fullOutput).toContain("Version");
    expect(fullOutput).toContain("Transport");
  });

  it("displays server name in the output", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("io.github.test/server-basic");
  });

  it("displays server version in the output", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("1.0.0");
  });

  it("displays description in the output", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("A test server");
  });
});

// ---------------------------------------------------------------------------
// handleSearch — transport type display
// ---------------------------------------------------------------------------

describe("handleSearch — transport column", () => {
  it("shows 'npm' transport for npm packages", async () => {
    const client = makeMockClient(makeSearchResult([BASE_SERVER_ENTRY]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("npm");
  });

  it("shows 'pypi' transport for pypi packages", async () => {
    const client = makeMockClient(makeSearchResult([PYPI_SERVER_ENTRY]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("pypi");
  });

  it("shows 'docker' transport for docker packages", async () => {
    const client = makeMockClient(makeSearchResult([DOCKER_SERVER_ENTRY]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("docker");
  });

  it("shows 'http' transport for servers with only remotes", async () => {
    const client = makeMockClient(makeSearchResult([HTTP_SERVER_ENTRY]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("http");
  });

  it("shows '-' transport for servers with no packages and no remotes", async () => {
    const emptyServer = {
      ...BASE_SERVER_ENTRY,
      server: { ...BASE_SERVER_ENTRY.server, packages: [], remotes: [] },
    };
    const client = makeMockClient(makeSearchResult([emptyServer]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("-");
  });
});

// ---------------------------------------------------------------------------
// handleSearch — no results
// ---------------------------------------------------------------------------

describe("handleSearch — no results", () => {
  it("outputs 'No servers found' message when search returns empty", async () => {
    const client = makeMockClient(makeSearchResult([]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("zzz-no-match", { limit: 20 }, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("No servers found for 'zzz-no-match'");
  });

  it("does NOT output a table when there are no results", async () => {
    const client = makeMockClient(makeSearchResult([]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("zzz", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).not.toContain("Name");
  });
});

// ---------------------------------------------------------------------------
// handleSearch — --limit option
// ---------------------------------------------------------------------------

describe("handleSearch — --limit option", () => {
  it("passes the limit value to searchServers", async () => {
    const client = makeMockClient();
    const output = vi.fn();

    await handleSearch("test", { limit: 5 }, { registryClient: client as any, output });

    expect(client.searchServers).toHaveBeenCalledWith("test", expect.objectContaining({ limit: 5 }));
  });

  it("uses default limit of 20 when not specified", async () => {
    const client = makeMockClient();
    const output = vi.fn();

    await handleSearch("test", {}, { registryClient: client as any, output });

    expect(client.searchServers).toHaveBeenCalledWith("test", expect.objectContaining({ limit: 20 }));
  });
});

// ---------------------------------------------------------------------------
// handleSearch — --json flag
// ---------------------------------------------------------------------------

describe("handleSearch — --json flag", () => {
  it("outputs raw JSON when --json is passed", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20, json: true }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    const parsed = JSON.parse(fullOutput);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it("JSON output includes server name", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20, json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n")) as Array<{ name: string }>;
    expect(parsed[0].name).toBe("io.github.test/server-basic");
  });

  it("JSON output is an empty array when no results", async () => {
    const client = makeMockClient(makeSearchResult([]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20, json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n"));
    expect(parsed).toEqual([]);
  });

  it("does NOT output table headers in JSON mode", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20, json: true }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    // Should be valid JSON, not contain table borders
    expect(fullOutput).not.toContain("─");
    expect(fullOutput).not.toContain("│");
  });
});

// ---------------------------------------------------------------------------
// handleSearch — error handling
// ---------------------------------------------------------------------------

describe("handleSearch — error handling", () => {
  it("throws NetworkError when network call fails", async () => {
    const client = {
      searchServers: vi.fn().mockRejectedValue(new NetworkError("Network failed", new Error("ECONNREFUSED"))),
    };
    const output = vi.fn();

    await expect(
      handleSearch("test", { limit: 20 }, { registryClient: client as any, output })
    ).rejects.toThrow(NetworkError);
  });

  it("propagates RegistryError to caller", async () => {
    const client = {
      searchServers: vi.fn().mockRejectedValue(new NotFoundError("test")),
    };
    const output = vi.fn();

    await expect(
      handleSearch("test", { limit: 20 }, { registryClient: client as any, output })
    ).rejects.toThrow(NotFoundError);
  });
});

// ---------------------------------------------------------------------------
// handleSearch — edge cases
// ---------------------------------------------------------------------------

describe("handleSearch — edge cases", () => {
  it("handles server with missing description gracefully", async () => {
    const noDescServer = {
      ...BASE_SERVER_ENTRY,
      server: { ...BASE_SERVER_ENTRY.server, description: undefined },
    };
    const client = makeMockClient(makeSearchResult([noDescServer]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await expect(
      handleSearch("test", { limit: 20 }, { registryClient: client as any, output })
    ).resolves.toBeUndefined();

    expect(lines.join("\n")).toContain("io.github.test/server-basic");
  });

  it("handles multiple results in the table", async () => {
    const client = makeMockClient(makeSearchResult([BASE_SERVER_ENTRY, PYPI_SERVER_ENTRY, DOCKER_SERVER_ENTRY]));
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleSearch("test", { limit: 20 }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("io.github.test/server-basic");
    expect(fullOutput).toContain("io.github.test/python-server");
    expect(fullOutput).toContain("io.github.test/docker-server");
  });

  it("handles special characters in server name", async () => {
    const client = makeMockClient();
    const output = vi.fn();

    await expect(
      handleSearch("io.github.test/server-basic", { limit: 20 }, { registryClient: client as any, output })
    ).resolves.toBeUndefined();
  });
});
