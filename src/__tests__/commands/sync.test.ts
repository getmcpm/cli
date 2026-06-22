import { describe, it, expect, vi } from "vitest";
import { handleSync, exitCodeFor, type SyncDeps, type SyncResult } from "../../commands/sync.js";
import type { DriftModel } from "../../config/drift.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";

// Build deps whose clients each return a fixed server map.
function makeDeps(
  configs: Partial<Record<ClientId, Record<string, McpServerEntry>>>,
  output: (t: string) => void,
): SyncDeps {
  const ids = Object.keys(configs) as ClientId[];
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(ids),
    getAdapter: vi.fn((id: ClientId) => ({
      read: vi.fn().mockResolvedValue(configs[id] ?? {}),
    })),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    output,
  };
}

function capture() {
  const lines: string[] = [];
  return { output: (t: string) => lines.push(t), text: () => lines.join("\n") };
}

describe("handleSync", () => {
  it("reports no drift when every client has the same servers", async () => {
    const cap = capture();
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const deps = makeDeps(
      { "claude-desktop": { fs: entry }, cursor: { fs: { ...entry } } },
      cap.output,
    );
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(false);
    expect(result.model.inSync).toBe(1);
    expect(cap.text()).toMatch(/in sync/i);
  });

  it("flags a server missing from one client and sets drift=true", async () => {
    const cap = capture();
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const deps = makeDeps(
      { "claude-desktop": { fs: entry }, cursor: {} },
      cap.output,
    );
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(true);
    const fs = result.model.servers.find((s) => s.name === "fs")!;
    expect(fs.absent).toEqual(["cursor"]);
    // matrix shows present (✓) and absent (·)
    expect(cap.text()).toContain("✓");
    expect(cap.text()).toContain("·");
  });

  it("renders a conflict cell (≠) and sets drift=true on a shape conflict", async () => {
    const cap = capture();
    const deps = makeDeps(
      {
        "claude-desktop": { gh: { command: "npx", env: { TOKEN: "a" } } },
        cursor: { gh: { command: "uvx", env: { TOKEN: "a" } } },
      },
      cap.output,
    );
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(true);
    expect(cap.text()).toContain("≠");
  });

  it("emits the DriftModel verbatim under --json (and no table)", async () => {
    const cap = capture();
    const deps = makeDeps(
      { "claude-desktop": { fs: { command: "npx" } }, cursor: {} },
      cap.output,
    );
    const result = await handleSync({ json: true }, deps);
    const parsed = JSON.parse(cap.text());
    expect(parsed).toEqual(result.model);
    expect(cap.text()).not.toContain("✓");
  });

  it("does not flag drift when only one client has a readable config", async () => {
    const cap = capture();
    const deps = makeDeps({ "claude-desktop": { fs: { command: "npx" } } }, cap.output);
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(false);
    expect(cap.text()).toMatch(/nothing to compare/i);
  });

  it("handles zero detected clients without throwing", async () => {
    const cap = capture();
    const deps = makeDeps({}, cap.output);
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(false);
    expect(result.model.clients).toEqual([]);
  });
});

describe("exitCodeFor (the --check CI gate)", () => {
  const emptyModel: DriftModel = { clients: [], servers: [], inSync: 0, drifted: 0 };
  const result = (drift: boolean): SyncResult => ({ model: emptyModel, drift });

  it("returns 2 only when --check is set AND drift was found", () => {
    expect(exitCodeFor(result(true), true)).toBe(2);
  });

  it("returns 0 when drift is found but --check is not set (informational run)", () => {
    expect(exitCodeFor(result(true), false)).toBe(0);
    expect(exitCodeFor(result(true), undefined)).toBe(0);
  });

  it("returns 0 when --check is set but there is no drift", () => {
    expect(exitCodeFor(result(false), true)).toBe(0);
  });
});
