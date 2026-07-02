/**
 * Tests for orchestrator.ts — enable/disable/status across mocked adapters.
 */

import { describe, expect, test } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import {
  enableGuardAcrossClients,
  disableGuardAcrossClients,
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

function makeDeps(adapters: Partial<Record<ClientId, ConfigAdapter>>): OrchestratorDeps {
  return {
    detectClients: async () => Object.keys(adapters) as ClientId[],
    getAdapter: (id) => {
      const a = adapters[id];
      if (!a) throw new Error(`No adapter for ${id}`);
      return a;
    },
    getConfigPath: (id) => `/tmp/fake/${id}/config.json`,
    wrapContext: wrapCtx,
  };
}

describe("enableGuardAcrossClients", () => {
  test("wraps every unwrapped server across detected clients", async () => {
    const claudeState: Record<string, McpServerEntry> = {
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
      "git-mcp": { command: "npx", args: ["-y", "git"] },
    };
    const cursorState: Record<string, McpServerEntry> = {
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
    };
    const deps = makeDeps({
      "claude-desktop": makeAdapter("claude-desktop", claudeState),
      cursor: makeAdapter("cursor", cursorState),
    });

    const summary = await enableGuardAcrossClients(deps);

    expect(summary.totalChanged).toBe(3);
    expect(summary.totalSkipped).toBe(0);
    expect(summary.errors).toBe(0);
    // Verify state mutated correctly
    expect(claudeState["fs-mcp"]?.args?.[0]).toBe("guard");
    expect(claudeState["git-mcp"]?.args?.[0]).toBe("guard");
    expect(cursorState["fs-mcp"]?.args?.[0]).toBe("guard");
  });

  test("skips already-wrapped servers (idempotent enable)", async () => {
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": wrapEntry("fs-mcp", { command: "npx", args: ["-y", "fs"] }, wrapCtx),
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const summary = await enableGuardAcrossClients(deps);
    expect(summary.totalChanged).toBe(0);
    expect(summary.totalSkipped).toBe(1);
    expect(summary.clients[0]?.servers[0]?.reason).toBe("already wrapped");
  });

  test("H9: DENIES HTTP-transport servers (no command field) by default", async () => {
    const state: Record<string, McpServerEntry> = {
      "http-mcp": { url: "https://example.com/mcp" },
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const summary = await enableGuardAcrossClients(deps);
    expect(summary.totalChanged).toBe(0);
    expect(summary.totalSkipped).toBe(1);
    const server = summary.clients[0]?.servers[0];
    expect(server?.status).toBe("skipped");
    // No longer a silent "deferred to V2" — an explicit informed-consent DENY.
    expect(server?.reason).toContain("DENIED");
    expect(server?.reason).toContain("UNGUARDED");
  });

  test("--server filter limits to one server", async () => {
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": { command: "npx", args: ["fs"] },
      "git-mcp": { command: "npx", args: ["git"] },
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const summary = await enableGuardAcrossClients(deps, { server: "fs-mcp" });
    expect(summary.totalChanged).toBe(1);
    expect(state["fs-mcp"]?.args?.[0]).toBe("guard"); // wrapped
    expect(state["git-mcp"]?.command).toBe("npx");    // untouched
    expect(state["git-mcp"]?.args).toEqual(["git"]);  // untouched
  });

  test("--client filter limits to one client", async () => {
    const claudeState: Record<string, McpServerEntry> = { a: { command: "x" } };
    const cursorState: Record<string, McpServerEntry> = { b: { command: "y" } };
    const deps = makeDeps({
      "claude-desktop": makeAdapter("claude-desktop", claudeState),
      cursor: makeAdapter("cursor", cursorState),
    });

    const summary = await enableGuardAcrossClients(deps, { client: "claude-desktop" });
    expect(summary.clients.map((c) => c.clientId)).toEqual(["claude-desktop"]);
    expect(claudeState.a?.args?.[0]).toBe("guard");
    expect(cursorState.b?.args?.[0]).toBeUndefined();
  });

  test("unknown --client filter throws", async () => {
    const deps = makeDeps({ cursor: makeAdapter("cursor", {}) });
    await expect(
      enableGuardAcrossClients(deps, { client: "claude-desktop" }),
    ).rejects.toThrow(/not detected/);
  });

  test("read error on one client is reported but doesn't block others", async () => {
    const cursorState: Record<string, McpServerEntry> = { a: { command: "x" } };
    const badAdapter: ConfigAdapter = {
      clientId: "claude-desktop",
      async read() { throw new Error("boom"); },
      async addServer() { throw new Error(); },
      async removeServer() { throw new Error(); },
      async setServerDisabled() { throw new Error(); },
      async replaceServer() { throw new Error(); },
    };
    const deps = makeDeps({
      "claude-desktop": badAdapter,
      cursor: makeAdapter("cursor", cursorState),
    });

    const summary = await enableGuardAcrossClients(deps);
    expect(summary.errors).toBe(1);
    expect(summary.totalChanged).toBe(1); // cursor still wrapped
  });
});

describe("disableGuardAcrossClients", () => {
  test("unwraps wrapped servers back to original entry", async () => {
    const orig = { command: "npx", args: ["-y", "fs"], env: { K: "V" } };
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": wrapEntry("fs-mcp", orig, wrapCtx),
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const summary = await disableGuardAcrossClients(deps);
    expect(summary.totalChanged).toBe(1);
    expect(state["fs-mcp"]).toEqual(orig);
  });

  test("skips unwrapped servers (idempotent disable)", async () => {
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const summary = await disableGuardAcrossClients(deps);
    expect(summary.totalChanged).toBe(0);
    expect(summary.totalSkipped).toBe(1);
  });
});

describe("statusAcrossClients", () => {
  test("reports wrapped + unwrapped counts per client", async () => {
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": wrapEntry("fs-mcp", { command: "x" }, wrapCtx),
      "git-mcp": { command: "y" },
    };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });

    const status = await statusAcrossClients(deps);
    expect(status.totalWrapped).toBe(1);
    expect(status.totalUnwrapped).toBe(1);
    expect(status.clients[0]?.servers).toContainEqual({ name: "fs-mcp", wrapped: true, unguarded: false });
    expect(status.clients[0]?.servers).toContainEqual({ name: "git-mcp", wrapped: false, unguarded: false });
  });
});

// ─────────────── F1: confineMarkers embedding ───────────────

describe("enableGuardAcrossClients — F1 confine markers", () => {
  test("embeds --confine-profile-hash for a mapped server; none for an unmapped one", async () => {
    const state: Record<string, McpServerEntry> = {
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
      "git-mcp": { command: "npx", args: ["-y", "git"] },
    };
    const hash = "a".repeat(64);
    const deps: OrchestratorDeps = {
      ...makeDeps({ cursor: makeAdapter("cursor", state) }),
      confineMarkers: new Map([["fs-mcp", { profileHash: hash, required: true }]]),
    };

    await enableGuardAcrossClients(deps);

    expect(state["fs-mcp"]?.args).toContain("--confine-profile-hash");
    expect(state["fs-mcp"]?.args).toContain(hash);
    expect(state["fs-mcp"]?.args).toContain("--confine-required");
    // Unmapped server is wrapped WITHOUT confine tokens.
    expect(state["git-mcp"]?.args?.[0]).toBe("guard");
    expect(state["git-mcp"]?.args).not.toContain("--confine-profile-hash");
  });

  test("no confineMarkers → no confine tokens (unchanged wraps)", async () => {
    const state: Record<string, McpServerEntry> = { "fs-mcp": { command: "npx", args: ["fs"] } };
    const deps = makeDeps({ cursor: makeAdapter("cursor", state) });
    await enableGuardAcrossClients(deps);
    expect(state["fs-mcp"]?.args).not.toContain("--confine-profile-hash");
  });
});
