import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "../../server/index.js";
import type { ServerDeps } from "../../server/handlers.js";
import type { ServerEntry } from "../../registry/types.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";
import { OFFICIAL_META_KEY } from "../../utils/format-trust.js";

function entry(status?: string, statusMessage?: string): ServerEntry {
  return {
    server: {
      name: "io.github.acme/example",
      version: "1.0.0",
      description: "A test server",
      packages: [{ registryType: "pypi", identifier: "example", version: "1.0.0", environmentVariables: [] }],
    },
    _meta: { [OFFICIAL_META_KEY]: { status, statusMessage, publishedAt: "2020-01-01T00:00:00Z" } },
  } as ServerEntry;
}

const connections: Array<{ client: Client; server: McpServer }> = [];
afterEach(async () => {
  for (const { client, server } of connections.splice(0)) {
    await client.close();
    await server.close();
  }
});

async function connect(entries: ServerEntry[] = [entry("active")], fail = false) {
  const deps: ServerDeps = {
    registrySearch: vi.fn(async () => {
      if (fail) throw new Error("Registry unavailable");
      return entries;
    }),
    registryGetServer: vi.fn(async () => {
      if (fail) throw new Error("Registry unavailable");
      return entries[0];
    }),
    scanTier1: vi.fn(scanTier1),
    computeTrustScore,
    detectClients: vi.fn(),
    getAdapter: vi.fn(),
    getConfigPath: vi.fn(),
    addToStore: vi.fn(),
    removeFromStore: vi.fn(),
  };
  const server = new McpServer({ name: "mcpm-evidence-test", version: "0.0.0" });
  registerTools(server, deps);
  const client = new Client({ name: "evidence-consumer", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  connections.push({ client, server });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return { client, deps };
}

describe("agent evidence on the MCP wire", () => {
  it("advertises versioned output schemas only on search and info", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.filter((t) => t.outputSchema).map((t) => t.name).sort()).toEqual(["mcpm_info", "mcpm_search"]);
    for (const tool of tools.filter((t) => t.outputSchema)) {
      expect(tool.outputSchema?.properties?.schemaVersion).toMatchObject({ const: 1 });
    }
  });

  it("keeps legacy text and scalar scores while exposing denominator, ceiling and coverage", async () => {
    const { client, deps } = await connect();
    const result = await client.callTool({ name: "mcpm_search", arguments: { query: "example" } });
    expect(result.isError, JSON.stringify(result.content)).not.toBe(true);
    const content = result.content as Array<{ type: string; text: string }>;
    const data = JSON.parse(content[0].text);
    expect(result.structuredContent).toEqual(data);
    expect(data.schemaVersion).toBe(1);
    expect(data.servers[0]).toMatchObject({
      name: "io.github.acme/example", trustScore: 62, maxPossible: 80, level: "caution",
      registryStatus: { status: "active", statusMessage: null, blocksInstall: false },
      assessment: {
        maxAchievableScore: 62,
        findings: [],
        checks: { staticScan: "completed", healthCheck: "not_run", externalScan: "not_run", releaseCooldown: "not_run", packageIntegrity: "not_run", provenance: "not_run" },
      },
    });
    expect(deps.scanTier1).toHaveBeenCalledTimes(1);
    expect(deps.detectClients).not.toHaveBeenCalled();
    expect(deps.addToStore).not.toHaveBeenCalled();
  });

  it.each(["deleted", "deprecated", undefined, "future-status"])("reports lifecycle %s without inventing approval", async (status) => {
    const { client } = await connect([entry(status)]);
    const result = await client.callTool({ name: "mcpm_info", arguments: { name: "io.github.acme/example" } });
    const data = result.structuredContent as { schemaVersion: number; trustScore: { score: number; maxPossible: number }; registryStatus: { status: string | null; statusMessage: string | null; blocksInstall: boolean }; assessment: { findings: Array<{ type: string }> } };
    expect(data.schemaVersion).toBe(1);
    expect(data.trustScore.maxPossible).toBe(80);
    expect(data.registryStatus.status).toBe(status ?? null);
    expect(data.registryStatus.blocksInstall).toBe(status === "deleted");
    expect(data.assessment.findings.some((f) => f.type === "registry-status")).toBe(status === "deleted" || status === "deprecated");
    expect(data.registryStatus.statusMessage).toBeNull();
  });

  it("bounds and sanitizes the registry's untrusted explanation", async () => {
    const { client } = await connect([entry(" DELETED ", "\u001b[31m" + "x".repeat(500))]);
    const result = await client.callTool({ name: "mcpm_info", arguments: { name: "io.github.acme/example" } });
    const data = result.structuredContent as { registryStatus: { status: string; statusMessage: string; blocksInstall: boolean } };
    expect(data.registryStatus.status).toBe("deleted");
    expect(data.registryStatus.blocksInstall).toBe(true);
    expect(data.registryStatus.statusMessage).not.toContain("\u001b");
    expect(data.registryStatus.statusMessage.length).toBeLessThanOrEqual(256);
  });

  it.each(["mcpm_search", "mcpm_info"])("reports a %s registry outage as an error, never as clean evidence", async (name) => {
    const { client } = await connect([], true);
    const result = await client.callTool({ name, arguments: name === "mcpm_search" ? { query: "example" } : { name: "io.github.acme/example" } });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toBeUndefined();
  });
});
