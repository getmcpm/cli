import { describe, it, expect, vi } from "vitest";
import {
  buildDriftModel,
  collectClientStates,
  type ClientState,
  type DriftDeps,
} from "../../config/drift.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function state(clientId: ClientId, servers: Record<string, McpServerEntry>): ClientState {
  return { clientId, servers };
}

function findServer(model: ReturnType<typeof buildDriftModel>, name: string) {
  const s = model.servers.find((x) => x.name === name);
  if (!s) throw new Error(`server ${name} not in model`);
  return s;
}

// ---------------------------------------------------------------------------
// buildDriftModel — pure
// ---------------------------------------------------------------------------

describe("buildDriftModel", () => {
  it("marks a server present in every client with an identical shape as in-sync", () => {
    const entry: McpServerEntry = { command: "npx", args: ["-y", "fs"], env: { ROOT: "/a" } };
    const model = buildDriftModel([
      state("claude-desktop", { fs: entry }),
      state("cursor", { fs: { ...entry } }),
    ]);
    const fs = findServer(model, "fs");
    expect(fs.present.slice().sort()).toEqual(["claude-desktop", "cursor"]);
    expect(fs.absent).toEqual([]);
    expect(fs.conflict).toBe(false);
    expect(model.inSync).toBe(1);
    expect(model.drifted).toBe(0);
  });

  it("flags a server missing from one client (absent), among clients that HAVE configs", () => {
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const model = buildDriftModel([
      state("claude-desktop", { fs: entry }),
      state("cursor", { fs: { ...entry } }),
      state("vscode", {}),
    ]);
    const fs = findServer(model, "fs");
    expect(fs.present.slice().sort()).toEqual(["claude-desktop", "cursor"]);
    expect(fs.absent).toEqual(["vscode"]);
    expect(fs.conflict).toBe(false);
    expect(model.drifted).toBe(1);
    expect(model.inSync).toBe(0);
  });

  it("flags an env KEY-SET divergence as a conflict (reports the field)", () => {
    const model = buildDriftModel([
      state("claude-desktop", { gh: { command: "npx", env: { TOKEN: "x" } } }),
      state("cursor", { gh: { command: "npx", env: { TOKEN: "x", EXTRA: "y" } } }),
    ]);
    const gh = findServer(model, "gh");
    expect(gh.conflict).toBe(true);
    expect(gh.conflictFields).toContain("env keys");
    expect(model.drifted).toBe(1);
  });

  it("does NOT treat differing env VALUES (same keys) as a conflict — never compares secrets", () => {
    const model = buildDriftModel([
      state("claude-desktop", { gh: { command: "npx", env: { TOKEN: "secret-A" } } }),
      state("cursor", { gh: { command: "npx", env: { TOKEN: "secret-B" } } }),
    ]);
    const gh = findServer(model, "gh");
    expect(gh.conflict).toBe(false);
    expect(model.inSync).toBe(1);
  });

  it("ignores the per-client `disabled` flag (an intentional toggle, not definition drift)", () => {
    const model = buildDriftModel([
      state("claude-desktop", { fs: { command: "npx", args: ["fs"], disabled: true } }),
      state("cursor", { fs: { command: "npx", args: ["fs"], disabled: false } }),
    ]);
    expect(findServer(model, "fs").conflict).toBe(false);
    expect(model.inSync).toBe(1);
    expect(model.drifted).toBe(0);
  });

  it("flags a command divergence as a conflict", () => {
    const model = buildDriftModel([
      state("claude-desktop", { x: { command: "npx", args: ["x"] } }),
      state("cursor", { x: { command: "uvx", args: ["x"] } }),
    ]);
    const x = findServer(model, "x");
    expect(x.conflict).toBe(true);
    expect(x.conflictFields).toContain("command");
  });

  it("treats args order as significant (a reordering is a conflict)", () => {
    const model = buildDriftModel([
      state("claude-desktop", { x: { command: "npx", args: ["a", "b"] } }),
      state("cursor", { x: { command: "npx", args: ["b", "a"] } }),
    ]);
    expect(findServer(model, "x").conflict).toBe(true);
    expect(findServer(model, "x").conflictFields).toContain("args");
  });

  it("flags a header KEY-SET divergence for URL servers (never header values)", () => {
    const model = buildDriftModel([
      state("cursor", { api: { url: "https://x", headers: { Authorization: "Bearer a" } } }),
      state("vscode", { api: { url: "https://x", headers: { Authorization: "Bearer b", "X-Trace": "1" } } }),
    ]);
    const api = findServer(model, "api");
    expect(api.conflict).toBe(true);
    expect(api.conflictFields).toContain("header keys");
  });

  it("a single readable client yields no drift (nothing to compare)", () => {
    const model = buildDriftModel([
      state("claude-desktop", { a: { command: "npx" }, b: { command: "uvx" } }),
    ]);
    expect(model.drifted).toBe(0);
    expect(model.inSync).toBe(2);
    expect(model.clients).toEqual(["claude-desktop"]);
  });

  it("sorts servers by name and reports the considered clients", () => {
    const model = buildDriftModel([
      state("cursor", { zeta: { command: "npx" }, alpha: { command: "npx" } }),
      state("claude-desktop", { alpha: { command: "npx" } }),
    ]);
    expect(model.servers.map((s) => s.name)).toEqual(["alpha", "zeta"]);
    expect(model.clients.slice().sort()).toEqual(["claude-desktop", "cursor"]);
  });
});

// ---------------------------------------------------------------------------
// collectClientStates — I/O, injected
// ---------------------------------------------------------------------------

function makeDeps(overrides: Partial<DriftDeps> = {}): DriftDeps {
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop", "cursor"]),
    getAdapter: vi.fn().mockReturnValue({ read: vi.fn().mockResolvedValue({}) }),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    ...overrides,
  };
}

describe("collectClientStates", () => {
  it("returns one state per readable client", async () => {
    const deps = makeDeps({
      getAdapter: vi.fn((id: ClientId) => ({
        read: vi.fn().mockResolvedValue(id === "cursor" ? { fs: { command: "npx" } } : {}),
      })),
    });
    const states = await collectClientStates(deps);
    expect(states.map((s) => s.clientId)).toEqual(["claude-desktop", "cursor"]);
    expect(states[1]!.servers).toEqual({ fs: { command: "npx" } });
  });

  it("skips clients whose config is unreadable (does not throw)", async () => {
    const deps = makeDeps({
      getAdapter: vi.fn((id: ClientId) => ({
        read:
          id === "cursor"
            ? vi.fn().mockRejectedValue(new Error("malformed JSON"))
            : vi.fn().mockResolvedValue({ ok: { command: "npx" } }),
      })),
    });
    const states = await collectClientStates(deps);
    expect(states.map((s) => s.clientId)).toEqual(["claude-desktop"]);
  });
});

// ---------------------------------------------------------------------------
// #59: an entry dropped by read()'s shape validation (#23, v0.34.0) used to be
// indistinguishable from an entry that was never there — so `sync --check`
// reported a client that HAS the server as "missing" it (a false drift claim
// on a CI gate), or, when only one client had it, dropped the server from the
// model entirely and counted the run clean.
// ---------------------------------------------------------------------------

describe("buildDriftModel — malformed entries are not reported as absent", () => {
  it("reports a malformed entry as malformed, NOT missing, in that client", () => {
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const model = buildDriftModel([
      { clientId: "claude-desktop", servers: { fs: entry }, malformed: ["fs"] },
      state("cursor", { fs: { ...entry } }),
    ]);
    const fs = findServer(model, "fs");
    // claude-desktop HAS this server — saying it is "missing in claude-desktop"
    // is a false statement that sends the user to re-add a server they have.
    expect(fs.absent).toEqual([]);
    expect(fs.malformed).toEqual(["claude-desktop"]);
  });

  it("a malformed holder is excluded from the shape comparison", () => {
    // The malformed entry's shape is exactly what we could not validate, so it
    // must not manufacture a conflict against the good client.
    const model = buildDriftModel([
      { clientId: "claude-desktop", servers: {}, malformed: ["fs"] },
      state("cursor", { fs: { command: "npx", args: ["fs"] } }),
    ]);
    const fs = findServer(model, "fs");
    expect(fs.conflict).toBe(false);
    expect(fs.present).toEqual(["cursor"]);
  });

  it("surfaces a server that is malformed in the ONLY client holding it", () => {
    // Previously this vanished from the model: drifted 0, inSync 0, exit 0 —
    // a clean CI pass over a config mcpm could not actually read.
    const model = buildDriftModel([
      { clientId: "claude-desktop", servers: {}, malformed: ["fs"] },
      state("cursor", {}),
    ]);
    const fs = findServer(model, "fs");
    expect(fs.malformed).toEqual(["claude-desktop"]);
    expect(fs.present).toEqual([]);
    // Not verifiable ⇒ not in-sync. `sync --check` must not report clean.
    expect(model.inSync).toBe(0);
    expect(model.drifted).toBe(1);
  });

  it("does not count a fully-verified stack as drifted (negative control)", () => {
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const model = buildDriftModel([
      state("claude-desktop", { fs: entry }),
      state("cursor", { fs: { ...entry } }),
    ]);
    expect(findServer(model, "fs").malformed).toEqual([]);
    expect(model.drifted).toBe(0);
  });
});

describe("collectClientStates — records malformed entry names", () => {
  it("captures the names read() dropped, per client", async () => {
    const deps = makeDeps({
      getAdapter: vi.fn((id: ClientId) => ({
        read: vi.fn().mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
          if (id === "cursor") {
            onSkip?.("broken");
            return { ok: { command: "npx" } };
          }
          return { ok: { command: "npx" } };
        }),
      })),
    });
    const states = await collectClientStates(deps);
    expect(states.find((s) => s.clientId === "cursor")!.malformed).toEqual(["broken"]);
    expect(states.find((s) => s.clientId === "claude-desktop")!.malformed).toEqual([]);
  });
});
