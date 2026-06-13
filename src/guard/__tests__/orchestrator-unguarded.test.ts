/**
 * H9 Part A — orchestrator consent gate for `mcpm guard enable`.
 *
 * A URL/HTTP-transport server entry (no `command`) cannot be wrapped by the
 * stdio relay. The old behavior silently skipped it ("deferred to V2"); H9
 * makes it an explicit DENY-by-default with informed-consent opt-in via
 * `--allow-unguarded`. Even on consent it stays "skipped from wrap" (no relay
 * exists) but is recorded + marked visibly — never silently dropped.
 */

import { describe, expect, test, vi } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import {
  enableGuardAcrossClients,
  statusAcrossClients,
  type OrchestratorDeps,
} from "../orchestrator.js";
import { wrapEntry, type WrapContext } from "../wrap.js";

const wrapCtx: WrapContext = { mcpmBinary: "mcpm" };

function makeAdapter(clientId: ClientId, state: Record<string, McpServerEntry>): ConfigAdapter {
  return {
    clientId,
    async read() {
      return { ...state };
    },
    async addServer() { throw new Error("not used"); },
    async removeServer() { throw new Error("not used"); },
    async setServerDisabled() { throw new Error("not used"); },
    async replaceServer(_p, name, entry) {
      state[name] = { ...entry };
    },
  };
}

function makeDeps(
  adapters: Partial<Record<ClientId, ConfigAdapter>>,
  overrides: Partial<OrchestratorDeps> = {},
): OrchestratorDeps {
  return {
    detectClients: async () => Object.keys(adapters) as ClientId[],
    getAdapter: (id) => {
      const a = adapters[id];
      if (!a) throw new Error(`No adapter for ${id}`);
      return a;
    },
    getConfigPath: (id) => `/tmp/fake/${id}/config.json`,
    wrapContext: wrapCtx,
    ...overrides,
  };
}

describe("enableGuardAcrossClients — unguarded consent gate", () => {
  test("DENIES a url entry by default; a sibling stdio server is still wrapped", async () => {
    const state: Record<string, McpServerEntry> = {
      "http-mcp": { url: "https://example.com/mcp" },
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
    };
    const recordSpy = vi.fn(async () => {});
    const deps = makeDeps(
      { cursor: makeAdapter("cursor", state) },
      { readUnguardedConsent: async () => [], recordUnguardedConsent: recordSpy },
    );

    const summary = await enableGuardAcrossClients(deps);

    const http = summary.clients[0]?.servers.find((s) => s.name === "http-mcp");
    const fs = summary.clients[0]?.servers.find((s) => s.name === "fs-mcp");
    expect(http?.status).toBe("skipped");
    expect(http?.reason).toContain("DENIED");
    expect(http?.reason).toContain("UNGUARDED");
    expect(fs?.status).toBe("wrapped");
    // No consent given → nothing recorded.
    expect(recordSpy).not.toHaveBeenCalled();
  });

  test("--allow-unguarded → consented + recorded + visibly-unguarded; stdio sibling still wrapped", async () => {
    const state: Record<string, McpServerEntry> = {
      "http-mcp": { url: "https://example.com/mcp" },
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
    };
    const recordSpy = vi.fn(async () => {});
    const deps = makeDeps(
      { cursor: makeAdapter("cursor", state) },
      {
        allowUnguarded: true,
        readUnguardedConsent: async () => [],
        recordUnguardedConsent: recordSpy,
      },
    );

    const summary = await enableGuardAcrossClients(deps);

    const http = summary.clients[0]?.servers.find((s) => s.name === "http-mcp");
    const fs = summary.clients[0]?.servers.find((s) => s.name === "fs-mcp");
    // Consented: a distinct "unguarded" status, NOT a silent skip and NOT "wrapped".
    expect(http?.status).toBe("unguarded");
    expect(http?.reason).toContain("consented");
    expect(fs?.status).toBe("wrapped");
    // The consent was recorded to the store.
    expect(recordSpy).toHaveBeenCalledWith(["http-mcp"]);
  });

  test("summary counts unguarded servers distinctly from skipped (H9 totalUnguarded)", async () => {
    const state: Record<string, McpServerEntry> = {
      "http-mcp": { url: "https://example.com/mcp" }, // consented → unguarded
      "fs-mcp": { command: "npx", args: ["-y", "fs"] }, // → wrapped (changed)
      "wrapped-already": wrapEntry("wrapped-already", { command: "x" }, wrapCtx),
    };
    const deps = makeDeps(
      { cursor: makeAdapter("cursor", state) },
      {
        allowUnguarded: true,
        readUnguardedConsent: async () => [],
        recordUnguardedConsent: async () => {},
      },
    );

    const summary = await enableGuardAcrossClients(deps);
    expect(summary.totalChanged).toBe(1); // fs-mcp wrapped
    expect(summary.totalUnguarded).toBe(1); // http-mcp consented, counted apart
    expect(summary.totalSkipped).toBe(1); // wrapped-already, NOT counted as unguarded
  });

  test("a previously-consented url server is allowed without the flag (store hit)", async () => {
    const state: Record<string, McpServerEntry> = {
      "http-mcp": { url: "https://example.com/mcp" },
    };
    const deps = makeDeps(
      { cursor: makeAdapter("cursor", state) },
      {
        // allowUnguarded NOT set, but the store already lists this server.
        readUnguardedConsent: async () => ["http-mcp"],
        recordUnguardedConsent: async () => {},
      },
    );

    const summary = await enableGuardAcrossClients(deps);
    const http = summary.clients[0]?.servers.find((s) => s.name === "http-mcp");
    expect(http?.status).toBe("unguarded");
  });
});

describe("statusAcrossClients — marks unguarded servers visibly (H9 A.5)", () => {
  test("a url server is flagged unguarded:true; a wrapped stdio server is not", async () => {
    const { wrapEntry } = await import("../wrap.js");
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": wrapEntry("fs-mcp", { command: "x" }, wrapCtx),
      "http-mcp": { url: "https://example.com/mcp" },
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const status = await statusAcrossClients(deps);
    const servers = status.clients[0]?.servers ?? [];
    expect(servers).toContainEqual({ name: "fs-mcp", wrapped: true, unguarded: false });
    expect(servers).toContainEqual({ name: "http-mcp", wrapped: false, unguarded: true });
  });
});
