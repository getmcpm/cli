import { afterEach, describe, expect, it, vi } from "vitest";
import { Client as LegacyClient } from "@modelcontextprotocol/sdk/client/index.js";
import { Client as ModernClient } from "@modelcontextprotocol/client";
import { InMemoryTransport, McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { makeCheckConfigExists } from "../../commands/doctor.js";
import { DoctorOutput } from "../../server/tools.js";
import { registerTools } from "../../server/index.js";
import type { ServerDeps } from "../../server/handlers.js";
import type { ConfigAdapter } from "../../config/adapters/index.js";

const { access } = vi.hoisted(() => ({ access: vi.fn() }));
vi.mock("fs/promises", async original => ({ ...await original<typeof import("fs/promises")>(), access }));
vi.mock("child_process", async original => ({ ...await original<typeof import("child_process")>(), execFile: vi.fn((_cmd, _args, callback) => callback(new Error("Not on PATH"))) }));
const closers: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of closers.splice(0)) await close(); access.mockReset(); });
const secret = "synthetic-doctor-token-not-for-logging";

async function connect(era: "modern" | "legacy", scenario: "empty" | "issues" | "denied") {
  access.mockImplementation(async (file: string) => {
    if (scenario === "denied" && file.endsWith("cursor")) throw Object.assign(new Error("Config access denied"), { code: "EACCES" });
    if (file.endsWith("cursor") || (scenario === "issues" && /windsurf|vscode/.test(file))) return;
    throw Object.assign(new Error("Missing"), { code: "ENOENT" });
  });
  const deps = {
    getConfigPath: (id: string) => `/synthetic/${id}`,
    getAdapter: (id: string) => ({ read: async (_path: string, onSkipped?: (name: string) => void) => {
      if (id === "vscode") throw new SyntaxError("Malformed config");
      if (scenario !== "issues") return {};
      if (id === "cursor") {
        onSkipped?.("unreadable-entry");
        return { shared: { command: "uvx", args: ["one"] }, credentials: { command: "npx", env: { API_TOKEN: secret } } };
      }
      return { shared: { command: "uvx", args: ["two"] } };
    } }) as ConfigAdapter,
  } as ServerDeps;
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const wire: Array<Record<string, unknown>> = [];
  const send = serverTransport.send.bind(serverTransport);
  serverTransport.send = async message => { wire.push(message as Record<string, unknown>); await send(message); };
  const handle = serveStdio(() => {
    const server = new McpServer({ name: "doctor-fixture", version: "1" }); registerTools(server, deps); return server;
  }, { transport: serverTransport, legacy: "serve" });
  const client = era === "modern"
    ? new ModernClient({ name: "doctor-consumer", version: "1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } })
    : new LegacyClient({ name: "doctor-consumer", version: "1" });
  closers.push(async () => { await client.close(); await handle.close(); });
  await client.connect(clientTransport);
  return { client, wire };
}

describe("doctor existence evidence", () => {
  it.each(["ENOENT", "ENOTDIR"])("%s is missing, not a fatal access failure", async code => {
    access.mockRejectedValue(Object.assign(new Error("Missing path"), { code }));
    expect(await makeCheckConfigExists(() => "/synthetic/missing")("cursor")).toBe(false);
  });
  it.each(["EACCES", "EPERM", "EIO"])("%s remains unknown rather than missing", async code => {
    const error = Object.assign(new Error("Cannot inspect"), { code }); access.mockRejectedValue(error);
    await expect(makeCheckConfigExists(() => "/synthetic/unreadable")("cursor")).rejects.toBe(error);
  });
  it("does not hide path resolver errors as missing configs", async () => {
    const error = new Error("Cannot resolve config path");
    await expect(makeCheckConfigExists(() => { throw error; })("cursor")).rejects.toBe(error);
    expect(access).not.toHaveBeenCalled();
  });
});

for (const era of ["modern", "legacy"] as const) describe(`${era} doctor evidence`, () => {
  it("advertises the versioned schema and preserves empty/unassessed evidence", async () => {
    const { client } = await connect(era, "empty");
    const { tools } = await client.listTools();
    expect(tools.find(t => t.name === "mcpm_doctor")?.outputSchema?.properties?.schemaVersion).toMatchObject({ const: 1 });
    const result = await client.callTool({ name: "mcpm_doctor", arguments: {} });
    expect(result.isError).not.toBe(true);
    const data = JSON.parse((result.content[0] as { text: string }).text);
    expect(result.structuredContent).toEqual(data);
    expect(DoctorOutput.safeParse(result.structuredContent).success).toBe(true);
    expect(data).toMatchObject({ schemaVersion: 1, ok: true, crossClient: null, issues: [], secrets: [] });
    expect(data.clients.find((c: { id: string }) => c.id === "claude-desktop")).toMatchObject({ exists: false, malformed: false, serverCount: 0 });
    expect(data.runtimes.every((r: { available: boolean }) => !r.available)).toBe(true);
    expect(DoctorOutput.safeParse({ ...data, schemaVersion: 2 }).success).toBe(false);
    expect(DoctorOutput.safeParse({ ...data, issues: undefined }).success).toBe(false);
    const additive = { ...data, future: true, clients: data.clients.map((c: object) => ({ ...c, future: true })) };
    expect(DoctorOutput.parse(additive)).toEqual(additive);
  });

  it("retains malformed configs, skipped entries, runtime failures, advisory drift and value-free secret findings", async () => {
    const { client, wire } = await connect(era, "issues");
    const result = await client.callTool({ name: "mcpm_doctor", arguments: {} });
    expect(result.isError).not.toBe(true);
    const data = JSON.parse((result.content[0] as { text: string }).text);
    expect(result.structuredContent).toEqual(data);
    expect(DoctorOutput.safeParse(result.structuredContent).success).toBe(true);
    expect(data.ok).toBe(false);
    expect(data.clients.find((c: { id: string }) => c.id === "vscode")).toMatchObject({ exists: true, malformed: true });
    expect(data.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ kind: "malformed-config", message: expect.stringContaining("unreadable-entry") }),
      expect.objectContaining({ kind: "missing-runtime", message: expect.stringContaining("uvx") }),
    ]));
    expect(data.crossClient).toMatchObject({ consistent: false, clientCount: 2 });
    expect(data.crossClient.drift).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "shared", kind: "conflict", fields: ["args"] }),
      expect.objectContaining({ name: "unreadable-entry", kind: "unreadable", present: [], malformed: ["cursor"] }),
    ]));
    expect(data.secrets).toEqual([expect.objectContaining({ client: "cursor", server: "credentials", field: "env", key: "API_TOKEN" })]);
    expect(JSON.stringify(result)).not.toContain(secret);
    if (era === "modern") expect(wire.some(m => (m.result as { resultType?: string })?.resultType === "complete")).toBe(true);
  });

  it("does not turn denied config access into clean success evidence", async () => {
    const { client } = await connect(era, "denied");
    const result = await client.callTool({ name: "mcpm_doctor", arguments: {} });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toBeUndefined();
    expect((result.content[0] as { text: string }).text).toContain("Config access denied");
  });
});
