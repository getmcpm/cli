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

// #59: drive read()'s onSkip the way the real BaseAdapter does for an entry
// that fails shape validation, so the whole `sync` path (collect -> model ->
// render) is exercised rather than a hand-built model.
function makeDepsWithMalformed(
  configs: Partial<Record<ClientId, Record<string, McpServerEntry>>>,
  malformed: Partial<Record<ClientId, string[]>>,
  output: (t: string) => void,
): SyncDeps {
  const ids = Object.keys(configs) as ClientId[];
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(ids),
    getAdapter: vi.fn((id: ClientId) => ({
      read: vi.fn().mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
        for (const name of malformed[id] ?? []) onSkip?.(name);
        return configs[id] ?? {};
      }),
    })),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    output,
  };
}

describe("handleSync — unreadable entries are not reported as missing", () => {
  it("renders ? (not ·) for a client whose entry read() dropped", async () => {
    const cap = capture();
    const deps = makeDepsWithMalformed(
      { "claude-desktop": {}, cursor: { fs: { command: "npx", args: ["fs"] } } },
      { "claude-desktop": ["fs"] },
      cap.output,
    );
    const result = await handleSync({}, deps);
    const fs = result.model.servers.find((s) => s.name === "fs")!;
    expect(fs.absent).toEqual([]);
    expect(fs.malformed).toEqual(["claude-desktop"]);
    // Assert on the MATRIX ROW, not the whole output: the detail line below the
    // table also contains "?", so a bare toContain("?") passes even when the
    // cell is wrong (verified — that assertion survived the cell-order mutant).
    const row = cap
      .text()
      .split("\n")
      .find((l) => l.includes("fs") && l.includes("\u2502"))!;
    expect(row).toContain("?");
    expect(row).not.toContain("\u00b7"); // not rendered as absent
    // The false claim this fixes: it must NOT say the server is missing there.
    expect(cap.text()).not.toMatch(/missing in claude-desktop/);
    expect(cap.text()).toMatch(/does not match the expected shape/);
  });

  it("sets drift=true (exit 2) when the only holder's entry is unreadable", async () => {
    const cap = capture();
    const deps = makeDepsWithMalformed(
      { "claude-desktop": {}, cursor: {} },
      { "claude-desktop": ["fs"] },
      cap.output,
    );
    const result = await handleSync({}, deps);
    expect(result.drift).toBe(true);
    expect(exitCodeFor(result, true)).toBe(2);
    // The summary must state a cause: "1 drifted (0 missing, 0 conflicts)" is
    // a drift count with nothing behind it.
    expect(cap.text()).toMatch(/1 drifted \(.*1 unreadable\)/);
  });
});

describe("handleSync — unreadable rendering details", () => {
  it("does not ALSO list a malformed-only server under missing", async () => {
    // present is empty for a malformed-only name, which rendered as
    // "· orphan: in ; missing in cursor" beside the ? line, and counted the
    // server under "missing in >=1 client" as well.
    const cap = capture();
    const deps = makeDepsWithMalformed(
      { "claude-desktop": {}, cursor: {} },
      { "claude-desktop": ["orphan"] },
      cap.output,
    );
    await handleSync({}, deps);
    expect(cap.text()).not.toMatch(/· orphan: in ;/);
    expect(cap.text()).toMatch(/also missing in cursor/);
    // The fact is stated ONCE in the body (folded into the ? line), but the
    // summary sub-count must stay true to its own label: orphan IS missing
    // from cursor, so "missing in >=1 client" is 1, not 0.
    expect(cap.text()).toMatch(/1 missing in ≥1 client/);
  });

  it("prints a legend entry for the ? cell", async () => {
    const cap = capture();
    const deps = makeDepsWithMalformed(
      { "claude-desktop": {}, cursor: { fs: { command: "npx" } } },
      { "claude-desktop": ["fs"] },
      cap.output,
    );
    await handleSync({}, deps);
    expect(cap.text()).toMatch(/legend:.*\? unreadable entry/);
  });

  it("does not append \", 0 unreadable\" when there are none", async () => {
    const cap = capture();
    const entry: McpServerEntry = { command: "npx", args: ["fs"] };
    const deps = makeDeps(
      { "claude-desktop": { fs: entry }, cursor: { fs: { ...entry } } },
      cap.output,
    );
    await handleSync({}, deps);
    // The LEGEND always names the ? cell, so assert on the summary line only.
    expect(cap.text()).toMatch(/0 shape conflicts\)/);
    expect(cap.text()).not.toMatch(/, \d+ unreadable\)/);
  });

  it("sanitizes a config-supplied name before it reaches the terminal", async () => {
    const cap = capture();
    const deps = makeDepsWithMalformed(
      { "claude-desktop": {}, cursor: {} },
      { "claude-desktop": ["ev\u001b]0;PWNED\u0007il"] },
      cap.output,
    );
    await handleSync({}, deps);
    expect(cap.text()).toContain("PWNED");
    expect(cap.text()).not.toContain("\u001b");
  });
});

describe("handleSync — reporting must not be gated on the matrix (#59/H1)", () => {
  it("names the entry when there is only ONE client, and still exits 2", async () => {
    // `drifted` comes from the model, so --check exited 2 while the ONLY line
    // printed was "nothing to compare across clients" — a CI failure whose own
    // output said there was nothing to look at. Single client is the common
    // desktop shape.
    const cap = capture();
    const deps = makeDepsWithMalformed({ "claude-desktop": {} }, { "claude-desktop": ["bad"] }, cap.output);
    const result = await handleSync({}, deps);
    expect(cap.text()).toContain("bad");
    expect(cap.text()).toMatch(/does not match the expected shape/);
    expect(exitCodeFor(result, true)).toBe(2);
  });

  it("names a client whose whole config is unparseable, and fails --check", async () => {
    // Otherwise the LARGER failure is the quieter one: one mis-typed entry
    // failed CI while an entirely broken config passed silently.
    const cap = capture();
    const deps: SyncDeps = {
      detectClients: vi
        .fn<() => Promise<ClientId[]>>()
        .mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn((id: ClientId) => ({
        read:
          id === "claude-desktop"
            ? vi.fn().mockRejectedValue(new SyntaxError("Unexpected token"))
            : vi.fn().mockResolvedValue({ fs: { command: "npx" } }),
      })),
      getPath: vi.fn().mockReturnValue("/mock/config.json"),
      output: cap.output,
    };
    const result = await handleSync({}, deps);
    expect(cap.text()).toMatch(/claude-desktop: config could not be read at all/);
    expect(exitCodeFor(result, true)).toBe(2);
  });
});
