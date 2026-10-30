import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport, McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { registerTools } from "../../server/index.js";
import { InfoOutput, SearchOutput, TOOL_DEFINITIONS } from "../../server/tools.js";
import type { ServerDeps } from "../../server/handlers.js";
import type { ServerEntry } from "../../registry/types.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of closers.splice(0)) await close(); });
async function connect(status = "active") {
  const entry = {
    server: { name: "io.github.acme/example", version: "1.0.0", description: "Synthetic server", packages: [{ registryType: "pypi", identifier: "example", version: "1.0.0", environmentVariables: [] }] },
    _meta: { "io.modelcontextprotocol.registry/official": { status, publishedAt: "2020-01-01T00:00:00Z" } },
  } as ServerEntry;
  const deps: ServerDeps = {
    registrySearch: vi.fn(async () => [entry]), registryGetServer: vi.fn(async () => entry),
    scanTier1, computeTrustScore, detectClients: vi.fn(async () => []),
    getAdapter: vi.fn(), getConfigPath: vi.fn(), addToStore: vi.fn(), removeFromStore: vi.fn(),
  };
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const messages: Array<{ result?: Record<string, unknown> }> = [];
  const send = serverTransport.send.bind(serverTransport);
  serverTransport.send = async message => { messages.push(message as typeof messages[number]); await send(message); };
  const handle = serveStdio(() => {
    const server = new McpServer({ name: "mcpm", version: "test" });
    registerTools(server, deps);
    return server;
  }, { transport: serverTransport, legacy: "serve" });
  const client = new Client({ name: "modern-test", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
  closers.push(async () => { await client.close(); await handle.close(); });
  await client.connect(clientTransport);
  return { client, deps, messages };
}

describe("modern MCP server wire contract", () => {
  it("negotiates modern and lists the same nine strict tools deterministically", async () => {
    const { client } = await connect();
    expect(client.getNegotiatedProtocolVersion()).toBe("2026-07-28");
    const first = await client.listTools(), second = await client.listTools();
    expect(first.tools.map(t => t.name)).toEqual(TOOL_DEFINITIONS.map(t => t.name));
    expect(second.tools).toEqual(first.tools);
    expect(first.tools.every(t => t.inputSchema.additionalProperties === false)).toBe(true);
  });

  it.each(["mcpm_search", "mcpm_install"])("rejects extra arguments before invoking %s", async name => {
    const { client, deps } = await connect();
    const args = name === "mcpm_search" ? { query: "example" } : { name: "io.github.acme/example" };
    const result = await client.callTool({ name, arguments: { ...args, extra: true } });
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toMatch(/Unrecognized key.*extra/i);
    expect(deps.registryGetServer).not.toHaveBeenCalled();
    expect(deps.registrySearch).not.toHaveBeenCalled();
    expect(deps.addToStore).not.toHaveBeenCalled();
  });

  it.each(["mcpm_search", "mcpm_info"])("preserves text and validates declared structured output for %s", async name => {
    const { client, messages } = await connect();
    const result = await client.callTool({ name, arguments: name === "mcpm_search" ? { query: "example" } : { name: "io.github.acme/example" } });
    expect(result.isError, JSON.stringify(result.content)).not.toBe(true);
    expect(messages.find(m => m.result?.structuredContent)?.result?.resultType).toBe("complete");
    expect((name === "mcpm_search" ? SearchOutput : InfoOutput).safeParse(result.structuredContent).success).toBe(true);
    expect(result.structuredContent).toEqual(JSON.parse((result.content[0] as { text: string }).text));
  });

  it("keeps deleted-server install refusal ahead of configuration or store writes", async () => {
    const { client, deps } = await connect("deleted");
    const result = await client.callTool({ name: "mcpm_install", arguments: { name: "io.github.acme/example" } });
    expect(result.isError).toBe(true);
    expect((result.content[0] as { text: string }).text).toContain('marked "deleted"');
    expect(deps.registryGetServer).toHaveBeenCalledWith("io.github.acme/example");
    expect(deps.getAdapter).not.toHaveBeenCalled();
    expect(deps.addToStore).not.toHaveBeenCalled();
  });
});
