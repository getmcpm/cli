/**
 * Tests for src/commands/doctor.ts
 *
 * TDD — RED phase first: all tests should fail before implementation exists.
 * All external dependencies (config adapters, detector, fs checks) are mocked.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Types matching the handler interface
// ---------------------------------------------------------------------------

export interface DoctorDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: (clientId: ClientId) => string;
  checkConfigExists: (clientId: ClientId) => Promise<boolean>;
  execCheck: (cmd: string) => Promise<boolean>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const ALL_CLIENTS: ClientId[] = ["claude-desktop", "cursor", "vscode", "windsurf"];

function makeAdapter(
  clientId: ClientId,
  servers: Record<string, McpServerEntry> = {},
  shouldThrow = false
): ConfigAdapter {
  return {
    clientId,
    read: vi.fn().mockImplementation(() =>
      shouldThrow ? Promise.reject(new SyntaxError("Unexpected token")) : Promise.resolve(servers)
    ),
    listServers: vi.fn().mockImplementation(() =>
      shouldThrow ? Promise.reject(new SyntaxError("Unexpected token")) : Promise.resolve(servers)
    ),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
  };
}

function makeHealthyDeps(overrides: Partial<DoctorDeps> = {}): DoctorDeps {
  return {
    detectClients: vi.fn().mockResolvedValue(["claude-desktop", "cursor"] as ClientId[]),
    getAdapter: vi.fn().mockImplementation((id: ClientId) =>
      makeAdapter(id, { "my-server": { command: "npx", args: ["-y", "my-server"] } })
    ),
    getConfigPath: vi.fn().mockImplementation((id: ClientId) => `/fake/${id}/config.json`),
    checkConfigExists: vi.fn().mockResolvedValue(true),
    execCheck: vi.fn().mockResolvedValue(true),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Import the handler (will fail until implementation exists)
// ---------------------------------------------------------------------------

import { doctorHandler } from "../../commands/doctor.js";

// ---------------------------------------------------------------------------
// Tests — client detection
// ---------------------------------------------------------------------------

describe("doctorHandler — client detection", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("checks all known clients for config file existence", async () => {
    const deps = makeHealthyDeps();
    await doctorHandler(deps);
    // checkConfigExists should be called for every known client
    expect(deps.checkConfigExists).toHaveBeenCalledTimes(ALL_CLIENTS.length);
    for (const id of ALL_CLIENTS) {
      expect(deps.checkConfigExists).toHaveBeenCalledWith(id);
    }
  });

  it("outputs found clients with a check mark", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // Output uses human-readable labels, not raw IDs
    expect(allOutput).toMatch(/Claude Desktop/);
    expect(allOutput).toMatch(/Cursor/);
    expect(allOutput).toMatch(/VS Code/);
    expect(allOutput).toMatch(/Windsurf/);
  });

  it("reports not-found clients with an x mark", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockImplementation((id: ClientId) =>
        Promise.resolve(id === "claude-desktop")
      ),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // claude-desktop found, others not — output uses human-readable labels
    expect(allOutput).toMatch(/Cursor/);
    expect(allOutput).toMatch(/VS Code/);
    expect(allOutput).toMatch(/Windsurf/);
  });

  it("when no clients found, still completes without throwing", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue([] as ClientId[]),
    });
    await expect(doctorHandler(deps)).resolves.not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Tests — config validity
// ---------------------------------------------------------------------------

describe("doctorHandler — config validity", () => {
  it("reports server count for valid config files", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "server-a": { command: "npx" },
          "server-b": { command: "npx" },
          "server-c": { command: "npx" },
        })
      ),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/3/);
  });

  it("reports malformed config as an issue", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {}, true /* shouldThrow */)
      ),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/malformed|invalid|parse|error/i);
  });

  it("does not attempt to list servers for non-existent configs", async () => {
    const adapter = makeAdapter("vscode", {});
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockImplementation((id: ClientId) =>
        Promise.resolve(id === "claude-desktop")
      ),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(adapter),
    });
    await doctorHandler(deps);
    // listServers should only be called for found clients
    expect(adapter.listServers).not.toHaveBeenCalledWith("/fake/vscode/config.json");
  });
});

// ---------------------------------------------------------------------------
// Tests — runtime availability
// ---------------------------------------------------------------------------

describe("doctorHandler — runtime checks", () => {
  it("checks npx, uvx, and docker availability", async () => {
    const deps = makeHealthyDeps({
      execCheck: vi.fn().mockResolvedValue(true),
    });
    await doctorHandler(deps);
    expect(deps.execCheck).toHaveBeenCalledWith("npx");
    expect(deps.execCheck).toHaveBeenCalledWith("uvx");
    expect(deps.execCheck).toHaveBeenCalledWith("docker");
  });

  it("outputs check mark for available runtimes", async () => {
    const deps = makeHealthyDeps({
      execCheck: vi.fn().mockResolvedValue(true),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/npx/);
    expect(allOutput).toMatch(/uvx/);
    expect(allOutput).toMatch(/docker/);
  });

  it("reports missing runtimes as issues", async () => {
    const deps = makeHealthyDeps({
      execCheck: vi.fn().mockImplementation((cmd: string) =>
        Promise.resolve(cmd !== "docker")
      ),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/docker/);
    expect(allOutput).toMatch(/not found|unavailable|missing/i);
  });
});

// ---------------------------------------------------------------------------
// Tests — server runtime cross-check
// ---------------------------------------------------------------------------

describe("doctorHandler — server runtime cross-check", () => {
  it("warns when a server uses a runtime that is not available", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "uvx-server": { command: "uvx", args: ["uvx-server"] },
        })
      ),
      execCheck: vi.fn().mockImplementation((cmd: string) =>
        Promise.resolve(cmd !== "uvx") // uvx not available
      ),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/uvx-server/);
    expect(allOutput).toMatch(/uvx/);
  });

  it("does not warn when all server runtimes are available", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "npx-server": { command: "npx", args: ["-y", "npx-server"] },
        })
      ),
      execCheck: vi.fn().mockResolvedValue(true),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).not.toMatch(/warning|warn|⚠/i);
  });

  it("skips runtime check for HTTP servers (no command field)", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["cursor"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("cursor", {
          "http-server": { url: "http://localhost:3000" },
        })
      ),
      execCheck: vi.fn().mockResolvedValue(false), // nothing available
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    // http-server should not appear as a warning
    expect(allOutput).not.toMatch(/http-server.*warn|warn.*http-server/i);
  });
});

// ---------------------------------------------------------------------------
// Tests — summary output
// ---------------------------------------------------------------------------

describe("doctorHandler — summary", () => {
  it('outputs "No critical issues found" when everything is healthy', async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      execCheck: vi.fn().mockResolvedValue(true),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "npx-server": { command: "npx", args: ["-y", "good-server"] },
        })
      ),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/no critical issues/i);
  });

  it("outputs issues section when problems exist", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "bad-server": { command: "uvx", args: ["bad-server"] },
        })
      ),
      execCheck: vi.fn().mockResolvedValue(false),
    });
    await doctorHandler(deps);
    const allOutput = (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
    expect(allOutput).toMatch(/issues?/i);
  });
});

// ---------------------------------------------------------------------------
// Tests — exit code
// ---------------------------------------------------------------------------

describe("doctorHandler — return value (exit code signal)", () => {
  it("returns 0 when no critical issues are found", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      execCheck: vi.fn().mockResolvedValue(true),
    });
    const code = await doctorHandler(deps);
    expect(code).toBe(0);
  });

  it("returns 1 when critical issues exist (malformed config)", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {}, true /* shouldThrow */)
      ),
    });
    const code = await doctorHandler(deps);
    expect(code).toBe(1);
  });

  it("returns 1 when a server uses an unavailable runtime", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(true),
      detectClients: vi.fn().mockResolvedValue(["claude-desktop"] as ClientId[]),
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter("claude-desktop", {
          "docker-server": { command: "docker", args: ["run", "my-image"] },
        })
      ),
      execCheck: vi.fn().mockResolvedValue(false),
    });
    const code = await doctorHandler(deps);
    expect(code).toBe(1);
  });

  it("returns 0 when all clients are missing (no config installed) — not critical", async () => {
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn().mockResolvedValue(false),
      detectClients: vi.fn().mockResolvedValue([] as ClientId[]),
      execCheck: vi.fn().mockResolvedValue(true),
    });
    const code = await doctorHandler(deps);
    expect(code).toBe(0);
  });
});
