import { afterEach, describe, expect, it, vi } from "vitest";
import { Client as LegacyClient } from "@modelcontextprotocol/sdk/client/index.js";
import { Client as ModernClient } from "@modelcontextprotocol/client";
import { InMemoryTransport, McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { registerTools } from "../../server/index.js";
import { AuditReportOutput } from "../../server/tools.js";
import type { ServerDeps } from "../../server/handlers.js";
import { readAuditInventory } from "../../store/audit-inventory.js";
import { handleAudit, type AuditDeps } from "../../commands/audit.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";
import { NetworkError } from "../../registry/errors.js";
import type { ServerEntry } from "../../registry/types.js";

const closers: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of closers.splice(0)) await close(); });
const row = { name: "io.github.test/example", version: "1.0.0", clients: [], installedAt: "2026-01-01T00:00:00Z" };
const secret = "synthetic-private-value";
const entry = { server: { name: row.name, version: "2.0.0", description: secret, packages: [], remotes: [] }, _meta: {} } as ServerEntry;

async function connect(era: "modern" | "legacy", raw = "[]", overrides: Partial<ServerDeps> = {}) {
  const deps: ServerDeps = {
    getAuditInventory: () => readAuditInventory(async () => raw),
    scannerConfigured: () => false, checkScannerAvailable: vi.fn(async () => false), scanTier2: vi.fn(async () => []),
    registryGetServer: vi.fn(async () => entry), scanTier1, computeTrustScore,
    registrySearch: vi.fn(), detectClients: vi.fn(), getAdapter: vi.fn(), getConfigPath: vi.fn(), addToStore: vi.fn(), removeFromStore: vi.fn(),
    ...overrides,
  };
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const wire: Array<{ result?: { resultType?: string } }> = [];
  const send = serverTransport.send.bind(serverTransport);
  serverTransport.send = async message => { wire.push(message as typeof wire[number]); await send(message); };
  const handle = serveStdio(() => {
    const server = new McpServer({ name: "audit-fixture", version: "1" }); registerTools(server, deps); return server;
  }, { transport: serverTransport, legacy: "serve" });
  const client = era === "modern"
    ? new ModernClient({ name: "audit-consumer", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } })
    : new LegacyClient({ name: "audit-consumer", version: "1" });
  closers.push(async () => { await client.close(); await handle.close(); });
  await client.connect(clientTransport);
  return { client, deps, wire };
}

for (const era of ["modern", "legacy"] as const) describe(`${era} mcpm_audit_report`, () => {
  it("advertises a closed input and additive versioned output; preserves empty inventory", async () => {
    const { client, deps, wire } = await connect(era);
    const { tools } = await client.listTools();
    const tool = tools.find(t => t.name === "mcpm_audit_report")!;
    expect(tool.inputSchema).toMatchObject({ properties: {}, additionalProperties: false });
    expect(tool.outputSchema?.properties?.schemaVersion).toMatchObject({ const: 1 });
    expect(tool.annotations?.readOnlyHint).toBe(true);
    const result = await client.callTool({ name: tool.name, arguments: {} });
    const data = JSON.parse((result.content[0] as { text: string }).text);
    expect(result.isError).not.toBe(true); expect(result.structuredContent).toEqual(data);
    expect(data).toMatchObject({ schemaVersion: 1, outcome: "empty_inventory", assessmentComplete: true, inventory: { state: "empty", presence: "present", total: 0 }, servers: [] });
    expect(AuditReportOutput.parse({ ...data, future: true, inventory: { ...data.inventory, future: true } })).toMatchObject({ future: true, inventory: { future: true } });
    expect(AuditReportOutput.safeParse({ ...data, schemaVersion: 2 }).success).toBe(false);
    expect(AuditReportOutput.safeParse({ ...data, inventory: undefined }).success).toBe(false);
    expect(deps.registryGetServer).not.toHaveBeenCalled(); expect(deps.checkScannerAvailable).not.toHaveBeenCalled();
    if (era === "modern") expect(wire.some(m => m.result?.resultType === "complete")).toBe(true);
    const invalid = await client.callTool({ name: tool.name, arguments: { fix: true } });
    expect(invalid.isError).toBe(true); expect(invalid.structuredContent).toBeUndefined();
    expect(deps.getAdapter).not.toHaveBeenCalled(); expect(deps.removeFromStore).not.toHaveBeenCalled();
  });

  it("matches CLI evidence, retains findings without values and leaves unselected checks not_run", async () => {
    const { client, deps } = await connect(era, JSON.stringify([row]), {
      scanTier1: () => [{ severity: "high", type: "secrets", message: secret, location: secret }],
    });
    const result = await client.callTool({ name: "mcpm_audit_report", arguments: {} });
    const data = result.structuredContent;
    expect(AuditReportOutput.safeParse(data).success).toBe(true);
    expect(data).toMatchObject({ outcome: "findings", assessmentComplete: true, servers: [{ checks: { registry: { state: "performed" }, static: { state: "performed" }, external: { state: "not_run", reason: "not-configured" }, health: { state: "not_run" } }, findings: [{ severity: "high", type: "secrets", source: "static" }] }] });
    const output = vi.fn();
    await handleAudit({ reportJson: true }, { ...deps, getServer: deps.registryGetServer, output } as unknown as AuditDeps);
    expect(JSON.parse(output.mock.calls[0][0])).toEqual(data);
    expect(JSON.stringify(result)).not.toContain(secret); expect(deps.scanTier2).not.toHaveBeenCalled();
  });

  it("keeps partial inventory and registry failure as incomplete evidence", async () => {
    const { client } = await connect(era, JSON.stringify([row, { secret }]), { registryGetServer: vi.fn().mockRejectedValue(new NetworkError(secret, new Error(secret))) });
    const result = await client.callTool({ name: "mcpm_audit_report", arguments: {} });
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).toMatchObject({ outcome: "incomplete_assessment", assessmentComplete: false, inventory: { state: "incomplete", total: 2, accepted: 1, issues: [{ code: "invalid-row", index: 1 }] }, summary: { assessed: 0, unassessed: 2 }, servers: [{ score: null, checks: { registry: { state: "unavailable" }, static: { state: "not_run" } } }] });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("keeps an opted-in unavailable scanner incomplete", async () => {
    const { client, deps } = await connect(era, JSON.stringify([row]), { scannerConfigured: () => true });
    const result = await client.callTool({ name: "mcpm_audit_report", arguments: {} });
    expect(result.structuredContent).toMatchObject({ assessmentComplete: false, outcome: "incomplete_assessment", servers: [{ checks: { external: { state: "unavailable" } } }] });
    expect(deps.checkScannerAvailable).toHaveBeenCalledOnce(); expect(deps.scanTier2).not.toHaveBeenCalled();
  });

  it("rejects malformed report output rather than emitting success evidence", async () => {
    const { client } = await connect(era, JSON.stringify([row]), {
      computeTrustScore: input => ({ ...computeTrustScore(input), score: secret }) as unknown as ReturnType<typeof computeTrustScore>,
    });
    const result = await client.callTool({ name: "mcpm_audit_report", arguments: {} });
    expect(result.isError).toBe(true); expect(result.structuredContent).toBeUndefined();
    expect((result.content[0] as { text: string }).text).toMatch(/output|validation|number/i);
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it("does not return structured success on a handler failure", async () => {
    const { client } = await connect(era, "[]", { getAuditInventory: async () => { throw new Error(secret); } });
    const result = await client.callTool({ name: "mcpm_audit_report", arguments: {} });
    expect(result.isError).toBe(true); expect(result.structuredContent).toBeUndefined();
    expect(JSON.stringify(result)).not.toContain(secret);
  });
});
