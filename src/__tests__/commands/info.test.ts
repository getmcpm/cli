/**
 * Tests for src/commands/info.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - RegistryClient.getServer is injected as a mock (no real network calls).
 * - output() is injected to capture output without process.stdout.write.
 * - Test handler functions directly — not Commander parsing.
 * - Cover: full details display, NotFoundError, NetworkError, --json flag.
 */

import { describe, it, expect, vi } from "vitest";
import type { ServerEntry } from "../../registry/types.js";
import { NotFoundError, NetworkError } from "../../registry/errors.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const FULL_SERVER_ENTRY: ServerEntry = {
  server: {
    name: "io.github.test/server-full",
    description: "A fully featured test server",
    title: "Full Test Server",
    version: "2.1.0",
    repository: { url: "https://github.com/test/server-full", source: "github" },
    websiteUrl: "https://example.com",
    icons: [{ src: "https://example.com/icon.png", mimeType: "image/png" }],
    packages: [
      {
        registryType: "npm",
        identifier: "@test/server-full",
        version: "2.1.0",
        transport: { type: "stdio" },
        environmentVariables: [
          { name: "API_KEY", description: "Your API key", isRequired: true, isSecret: true },
          { name: "DEBUG", description: "Enable debug mode", isRequired: false, isSecret: false },
          { name: "TIMEOUT", description: "Request timeout in ms", isRequired: false },
        ],
      },
    ],
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
      publishedAt: "2026-02-24T00:07:27.525636Z",
      updatedAt: "2026-03-01T00:00:00Z",
      isLatest: true,
    },
  },
};

const MINIMAL_SERVER_ENTRY: ServerEntry = {
  server: {
    name: "io.github.test/minimal",
    version: "0.1.0",
    packages: [],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      isLatest: true,
    },
  },
};

const PYPI_SERVER_ENTRY: ServerEntry = {
  server: {
    name: "io.github.test/pypi-server",
    description: "A PyPI server",
    version: "1.0.0",
    packages: [
      {
        registryType: "pypi",
        identifier: "my-mcp-server",
        version: "1.0.0",
        transport: { type: "stdio" },
        environmentVariables: [],
      },
    ],
  },
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: "active",
      publishedAt: "2026-01-15T00:00:00Z",
      isLatest: true,
    },
  },
};

function makeMockClient(entry: ServerEntry = FULL_SERVER_ENTRY) {
  return {
    searchServers: vi.fn(),
    getServer: vi.fn().mockResolvedValue(entry),
    getServerVersions: vi.fn(),
  };
}

// ---------------------------------------------------------------------------
// Import after fixture setup
// ---------------------------------------------------------------------------

import { handleInfo } from "../../commands/info.js";
import type { InfoOptions } from "../../commands/info.js";

// ---------------------------------------------------------------------------
// handleInfo — happy path
// ---------------------------------------------------------------------------

describe("handleInfo — happy path", () => {
  it("calls getServer with the provided name", async () => {
    const client = makeMockClient();
    const output = vi.fn();

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(client.getServer).toHaveBeenCalledWith("io.github.test/server-full");
  });

  it("displays the server name", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("io.github.test/server-full");
  });

  it("displays the server version", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("2.1.0");
  });

  it("displays the description", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("A fully featured test server");
  });

  it("displays the repository URL", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("https://github.com/test/server-full");
  });

  it("displays npm package identifier", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("@test/server-full");
  });

  it("displays pypi package identifier", async () => {
    const client = makeMockClient(PYPI_SERVER_ENTRY);
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/pypi-server", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("my-mcp-server");
  });

  it("displays remote HTTP URL", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("https://api.example.com/mcp");
  });

  it("displays environment variable names", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("API_KEY");
    expect(fullOutput).toContain("DEBUG");
    expect(fullOutput).toContain("TIMEOUT");
  });

  it("marks required env vars", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    // Should distinguish required vs optional
    const fullOutput = lines.join("\n");
    expect(fullOutput.toLowerCase()).toMatch(/required|optional/);
  });

  it("displays published date when available", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("2026-02-24");
  });

  it("displays status", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("active");
  });

  it("displays install footer with the server name", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).toContain("mcpm install");
    expect(fullOutput).toContain("io.github.test/server-full");
  });
});

// ---------------------------------------------------------------------------
// handleInfo — minimal server (optional fields absent)
// ---------------------------------------------------------------------------

describe("handleInfo — minimal server entry", () => {
  it("handles server with no description gracefully", async () => {
    const client = makeMockClient(MINIMAL_SERVER_ENTRY);
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await expect(
      handleInfo("io.github.test/minimal", {}, { registryClient: client as any, output })
    ).resolves.toBeUndefined();
  });

  it("handles server with no packages gracefully", async () => {
    const client = makeMockClient(MINIMAL_SERVER_ENTRY);
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await expect(
      handleInfo("io.github.test/minimal", {}, { registryClient: client as any, output })
    ).resolves.toBeUndefined();

    expect(lines.join("\n")).toContain("io.github.test/minimal");
  });

  it("handles server with no repository gracefully", async () => {
    const client = makeMockClient(MINIMAL_SERVER_ENTRY);
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await expect(
      handleInfo("io.github.test/minimal", {}, { registryClient: client as any, output })
    ).resolves.toBeUndefined();
  });

  it("handles server with no published date gracefully", async () => {
    const client = makeMockClient(MINIMAL_SERVER_ENTRY);
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await expect(
      handleInfo("io.github.test/minimal", {}, { registryClient: client as any, output })
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// handleInfo — --json flag
// ---------------------------------------------------------------------------

describe("handleInfo — --json flag", () => {
  it("outputs valid JSON when --json is passed", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", { json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n"));
    expect(parsed).toBeDefined();
  });

  it("JSON output includes the server name", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", { json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n")) as { name: string };
    expect(parsed.name).toBe("io.github.test/server-full");
  });

  it("JSON output includes packages array", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", { json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n")) as { packages: unknown[] };
    expect(Array.isArray(parsed.packages)).toBe(true);
    expect(parsed.packages).toHaveLength(1);
  });

  it("JSON output includes environment variables", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", { json: true }, { registryClient: client as any, output });

    const parsed = JSON.parse(lines.join("\n")) as { packages: Array<{ environmentVariables: unknown[] }> };
    expect(parsed.packages[0].environmentVariables).toHaveLength(3);
  });

  it("does NOT output decorative formatting in JSON mode", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", { json: true }, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput).not.toContain("─");
    expect(fullOutput).not.toContain("Install with:");
  });
});

// ---------------------------------------------------------------------------
// handleInfo — error handling
// ---------------------------------------------------------------------------

describe("handleInfo — error handling", () => {
  it("outputs 'Server not found' message for NotFoundError", async () => {
    const client = {
      getServer: vi.fn().mockRejectedValue(new NotFoundError("io.github.test/missing")),
    };
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/missing", {}, { registryClient: client as any, output });

    expect(lines.join("\n")).toContain("not found");
    expect(lines.join("\n")).toContain("io.github.test/missing");
  });

  it("does NOT throw for NotFoundError — handles it gracefully", async () => {
    const client = {
      getServer: vi.fn().mockRejectedValue(new NotFoundError("io.github.test/missing")),
    };
    const output = vi.fn();

    await expect(
      handleInfo("io.github.test/missing", {}, { registryClient: client as any, output })
    ).resolves.toBeUndefined();
  });

  it("throws NetworkError to the caller (non-recoverable)", async () => {
    const client = {
      getServer: vi.fn().mockRejectedValue(new NetworkError("Network failed", new Error("ECONNREFUSED"))),
    };
    const output = vi.fn();

    await expect(
      handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output })
    ).rejects.toThrow(NetworkError);
  });
});

// ---------------------------------------------------------------------------
// handleInfo — env var required/optional labeling
// ---------------------------------------------------------------------------

describe("handleInfo — env var required/optional labeling", () => {
  it("labels isRequired=true env vars as required", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    // API_KEY is required
    const apiKeyIdx = fullOutput.indexOf("API_KEY");
    const requiredIdx = fullOutput.indexOf("required", apiKeyIdx);
    expect(requiredIdx).toBeGreaterThan(-1);
  });

  it("labels isRequired=false env vars as optional", async () => {
    const client = makeMockClient();
    const lines: string[] = [];
    const output = (text: string) => lines.push(text);

    await handleInfo("io.github.test/server-full", {}, { registryClient: client as any, output });

    const fullOutput = lines.join("\n");
    expect(fullOutput.toLowerCase()).toContain("optional");
  });
});
