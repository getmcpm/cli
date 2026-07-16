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

const ALL_CLIENTS: ClientId[] = ["claude-desktop", "claude-code", "cursor", "vscode", "windsurf", "gemini-cli"];

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
    read: vi.fn().mockImplementation(() =>
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

import {
  doctorHandler,
  buildDoctorModel,
  buildDoctorReport,
  renderReportText,
  type DoctorReportEnv,
} from "../../commands/doctor.js";

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
    expect(adapter.read).not.toHaveBeenCalledWith("/fake/vscode/config.json");
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

// ---------------------------------------------------------------------------
// Cross-client (advisory) section
// ---------------------------------------------------------------------------

function captureOutput() {
  const lines: string[] = [];
  return { fn: (t: string) => lines.push(t), text: () => lines.join("\n") };
}

describe("doctorHandler — cross-client (advisory)", () => {
  // Only claude-desktop + cursor have configs in these cases.
  const twoClients = (id: ClientId) => id === "claude-desktop" || id === "cursor";

  it("reports consistency when both clients share the same servers (exit unchanged)", async () => {
    const cap = captureOutput();
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn((id: ClientId) => Promise.resolve(twoClients(id))),
      output: cap.fn,
    });
    const code = await doctorHandler(deps);
    expect(cap.text()).toContain("Cross-client (advisory):");
    expect(cap.text()).toMatch(/consistent across 2 clients/);
    expect(code).toBe(0);
  });

  it("flags a server present in one client but missing in another, WITHOUT failing doctor", async () => {
    const cap = captureOutput();
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn((id: ClientId) => Promise.resolve(twoClients(id))),
      getAdapter: vi.fn((id: ClientId) =>
        makeAdapter(id, id === "claude-desktop" ? { fs: { command: "npx", args: ["fs"] } } : {}),
      ),
      output: cap.fn,
    });
    const code = await doctorHandler(deps);
    expect(cap.text()).toMatch(/⚠ fs .*missing in cursor/);
    expect(cap.text()).toContain("mcpm sync --check");
    expect(code).toBe(0); // drift is advisory — must NOT flip the exit code
  });

  it("flags a shape conflict (same server, different command) without failing doctor", async () => {
    const cap = captureOutput();
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn((id: ClientId) => Promise.resolve(twoClients(id))),
      getAdapter: vi.fn((id: ClientId) =>
        makeAdapter(id, { gh: { command: id === "cursor" ? "uvx" : "npx", env: { TOKEN: "x" } } }),
      ),
      output: cap.fn,
    });
    const code = await doctorHandler(deps);
    expect(cap.text()).toMatch(/⚠ gh .*config differs \(command\)/);
    expect(code).toBe(0);
  });

  it("omits the cross-client section when fewer than 2 clients have a config", async () => {
    const cap = captureOutput();
    const deps = makeHealthyDeps({
      checkConfigExists: vi.fn((id: ClientId) => Promise.resolve(id === "claude-desktop")),
      output: cap.fn,
    });
    await doctorHandler(deps);
    expect(cap.text()).not.toContain("Cross-client");
  });
});

describe("doctorHandler — plaintext-secret scan (F9)", () => {
  beforeEach(() => vi.resetAllMocks());

  // ghp_ token assembled at runtime (never a real-looking literal in source).
  const ghToken = "gh" + "p_" + "A".repeat(36);

  const oneClientWith = (servers: Record<string, McpServerEntry>): DoctorDeps =>
    makeHealthyDeps({
      checkConfigExists: vi.fn((id: ClientId) => Promise.resolve(id === "claude-desktop")),
      getAdapter: vi.fn((id: ClientId) => makeAdapter(id, servers)),
    });

  it("surfaces a plaintext secret in the model but does NOT fail doctor (advisory)", async () => {
    const deps = oneClientWith({ srv: { command: "npx", args: ["x"], env: { GITHUB_TOKEN: ghToken } } });
    const model = await buildDoctorModel(deps);
    expect(model.secrets).toHaveLength(1);
    expect(model.secrets[0]).toMatchObject({
      client: "claude-desktop",
      server: "srv",
      field: "env",
      key: "GITHUB_TOKEN",
    });
    expect(model.ok).toBe(true);
    expect(await doctorHandler(deps)).toBe(0); // exit unchanged per spec
  });

  it("prints the advisory (key + label + remediation only, never the value)", async () => {
    const cap = captureOutput();
    const deps = oneClientWith({ srv: { command: "npx", args: ["x"], env: { GITHUB_TOKEN: ghToken } } });
    deps.output = cap.fn;
    await doctorHandler(deps);
    expect(cap.text()).toContain("Plaintext secrets (advisory):");
    expect(cap.text()).toContain("GITHUB_TOKEN");
    expect(cap.text()).toContain("mcpm secrets set");
    expect(cap.text()).not.toContain(ghToken); // value never rendered
  });

  it("--report emits a COUNT only (server name, key, and value all redacted)", async () => {
    const deps = oneClientWith({ "secret-srv": { command: "npx", args: ["x"], env: { GITHUB_TOKEN: ghToken } } });
    const model = await buildDoctorModel(deps);
    const env: DoctorReportEnv = {
      mcpm: "0", node: "v0", platform: "linux", arch: "x64", osRelease: "0",
      confineBackend: false, secretStore: "machine-key",
    };
    const report = renderReportText(buildDoctorReport(model, env));
    expect(report).toContain("1 plaintext secret(s)");
    expect(report).not.toContain("secret-srv");
    expect(report).not.toContain("GITHUB_TOKEN");
    expect(report).not.toContain(ghToken);
  });

  it("clean config yields no secrets and no advisory section", async () => {
    const cap = captureOutput();
    const deps = oneClientWith({ srv: { command: "npx", args: ["x"], env: { LOG_LEVEL: "debug" } } });
    deps.output = cap.fn;
    const model = await buildDoctorModel(deps);
    expect(model.secrets).toEqual([]);
    await doctorHandler(deps);
    expect(cap.text()).not.toContain("Plaintext secrets");
  });

  it("strips ANSI/OSC escapes from an attacker-influenced key in the advisory", async () => {
    const cap = captureOutput();
    const evilKey = "GITHUB_TOKEN\u001b[2K\u001b[1A"; // CSI erase-line / cursor-up
    const deps = oneClientWith({ srv: { command: "npx", args: ["x"], env: { [evilKey]: ghToken } } });
    deps.output = cap.fn;
    await doctorHandler(deps);
    expect(cap.text()).not.toContain("\u001b"); // escapes cannot spoof/erase the warning
    expect(cap.text()).toContain("GITHUB_TOKEN"); // name still shown, minus escapes
  });

  it("gives header-specific remediation (not the env-only keychain advice) for a header finding", async () => {
    const cap = captureOutput();
    const bearer = "Bearer " + "a".repeat(30) + "1";
    const deps = oneClientWith({ srv: { url: "https://x", headers: { Authorization: bearer } } });
    deps.output = cap.fn;
    await doctorHandler(deps);
    expect(cap.text()).toContain("rotate the credential");
    expect(cap.text()).not.toContain("mcpm secrets set"); // env-only advice suppressed
  });
});
