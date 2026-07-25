/**
 * MCP tool input schemas must be strict ON THE WIRE (security issue #31).
 *
 * `registerTool` accepts either a raw Zod shape or a whole schema. The
 * difference is easy to miss and silently weakens the surface: a raw shape is
 * rebuilt internally as a plain `z.object(shape)`, which DROPS the object-level
 * `strict` setting. Per-field constraints (length bounds, the client enum)
 * survive either way, so the loss is invisible in unit tests of the schemas
 * themselves — it only shows up over a real transport.
 *
 * These tests therefore drive an actual MCP client/server pair rather than
 * asserting on the Zod objects, because the Zod objects were already correct
 * while the wire behaviour was not.
 *
 * Guarantees pinned here:
 *   - every registered tool advertises `additionalProperties: false`
 *   - an unknown argument is REJECTED (JSON-RPC -32602), not silently dropped
 *   - valid calls are unaffected
 *   - the per-field bound and the client enum are still enforced
 */

import { describe, it, expect } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerTools } from "../../server/index.js";
import type { ServerDeps } from "../../server/handlers.js";

async function connectedClient(): Promise<Client> {
  const server = new McpServer({ name: "mcpm-test", version: "0.0.0" });
  // Registration does not invoke handlers, and every call in these tests is
  // rejected by validation before a handler would run.
  registerTools(server as never, {} as ServerDeps);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

/** Call a tool and report how it failed, without caring which mechanism failed it. */
async function callOutcome(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<{ rejected: boolean; detail: string }> {
  try {
    const res = (await client.callTool({ name, arguments: args })) as {
      isError?: boolean;
      content?: Array<{ text?: string }>;
    };
    return { rejected: res.isError === true, detail: res.content?.[0]?.text ?? "" };
  } catch (err) {
    return { rejected: true, detail: err instanceof Error ? err.message : String(err) };
  }
}

describe("MCP tool schemas are strict on the wire (#31)", () => {
  it("advertises additionalProperties:false for every tool", async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(0);

    const loose = tools
      .filter((t) => (t.inputSchema as { additionalProperties?: unknown }).additionalProperties !== false)
      .map((t) => t.name);

    // A tool registered with `.shape` instead of the whole schema lands here.
    expect(loose).toEqual([]);
  });

  it("rejects an unknown argument instead of silently dropping it", async () => {
    const client = await connectedClient();
    const { rejected, detail } = await callOutcome(client, "mcpm_search", {
      query: "filesystem",
      evil: "payload",
    });
    expect(rejected).toBe(true);
    expect(detail).toMatch(/unrecognized_keys|Unrecognized key|additional properties/i);
    expect(detail).toContain("evil");
  });

  it("rejects unknown arguments on a destructive tool too", async () => {
    const client = await connectedClient();
    const { rejected } = await callOutcome(client, "mcpm_install", {
      name: "io.github.example/server",
      surprise: true,
    });
    expect(rejected).toBe(true);
  });

  it("still enforces the bounded name length", async () => {
    const client = await connectedClient();
    const { rejected } = await callOutcome(client, "mcpm_info", { name: "a".repeat(300) });
    expect(rejected).toBe(true);
  });

  it("still enforces the client enum", async () => {
    const client = await connectedClient();
    const { rejected } = await callOutcome(client, "mcpm_list", { client: "not-a-real-client" });
    expect(rejected).toBe(true);
  });

  it("does not reject a well-formed call at the validation layer", async () => {
    const client = await connectedClient();
    const { detail } = await callOutcome(client, "mcpm_list", { client: "cursor" });
    // The handler runs against stub deps, so it may fail for its own reasons —
    // what matters is that it got PAST schema validation.
    expect(detail).not.toMatch(/unrecognized_keys|Invalid arguments/i);
  });
});
