/**
 * D7 tests: the structured DoctorModel + `--json` + the redacted `--report`,
 * plus the MCP `handleDoctor` regression (it used to hardcode `issues: []`).
 *
 * The security-critical assertion here is REDACTION: a server name that appears
 * in the model (including inside an issue message) must NOT leak into `--report`,
 * which is meant to be pasted into public bug reports.
 */

import { describe, it, expect, vi } from "vitest";
import type { ClientId } from "../../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../../config/adapters/index.js";
import {
  buildDoctorModel,
  buildDoctorReport,
  renderReportText,
  doctorHandler,
  type DoctorDeps,
  type DoctorModelDeps,
  type DoctorReportEnv,
} from "../../commands/doctor.js";
import { handleDoctor } from "../../server/handlers.js";
import type { ServerDeps } from "../../server/handlers.js";

// A wrapped entry: isWrapped() matches the contiguous ["guard","run","--inner"].
const WRAPPED: McpServerEntry = {
  command: "mcpm",
  args: ["guard", "run", "--inner", "--server-name", "x", "--", "npx", "srv"],
};

const ENV: DoctorReportEnv = {
  mcpm: "0.19.0",
  node: "v22.0.0",
  platform: "darwin",
  arch: "arm64",
  osRelease: "24.5.0",
  confineBackend: true,
  secretStore: "os-keychain",
};

function adapterFor(servers: Record<string, McpServerEntry>): ConfigAdapter {
  return {
    clientId: "claude-desktop",
    read: vi.fn().mockResolvedValue(servers),
    addServer: vi.fn(),
    removeServer: vi.fn(),
  } as unknown as ConfigAdapter;
}

/** Only claude-desktop has a config; runtimeAvail decides which runtimes exist. */
function modelDeps(
  servers: Record<string, McpServerEntry>,
  runtimeAvail: (cmd: string) => boolean
): DoctorModelDeps {
  return {
    getAdapter: () => adapterFor(servers),
    getConfigPath: (id: ClientId) => `/fake/${id}.json`,
    checkConfigExists: (id: ClientId) => Promise.resolve(id === "claude-desktop"),
    execCheck: (cmd: string) => Promise.resolve(runtimeAvail(cmd)),
  };
}

function fullDeps(
  servers: Record<string, McpServerEntry>,
  runtimeAvail: (cmd: string) => boolean,
  output: (t: string) => void
): DoctorDeps {
  return {
    ...modelDeps(servers, runtimeAvail),
    detectClients: vi.fn().mockResolvedValue([]),
    output,
  };
}

describe("buildDoctorModel (D7)", () => {
  it("counts guarded servers and flags a server on a missing runtime", async () => {
    const model = await buildDoctorModel(
      modelDeps(
        { "wrapped-one": WRAPPED, "secret-server-name": { command: "uvx", args: ["x"] } },
        (cmd) => cmd !== "uvx" // uvx unavailable
      )
    );
    const cd = model.clients.find((c) => c.id === "claude-desktop")!;
    expect(cd.serverCount).toBe(2);
    expect(cd.guardedCount).toBe(1);
    expect(model.issues.some((i) => i.kind === "missing-runtime")).toBe(true);
    expect(model.ok).toBe(false);
    expect(model.schemaVersion).toBe(1);
  });

  it("is healthy (ok=true, no issues) when every runtime is available", async () => {
    const model = await buildDoctorModel(
      modelDeps({ srv: { command: "npx", args: ["-y", "srv"] } }, () => true)
    );
    expect(model.ok).toBe(true);
    expect(model.issues).toHaveLength(0);
  });
});

describe("doctor --report redaction (D7)", () => {
  it("never leaks a server name — even one embedded in an issue message", async () => {
    const model = await buildDoctorModel(
      modelDeps({ "secret-server-name": { command: "uvx", args: ["x"] } }, (cmd) => cmd !== "uvx")
    );
    // Precondition: the model DOES carry the name (in the missing-runtime issue).
    expect(JSON.stringify(model)).toContain("secret-server-name");

    const text = renderReportText(buildDoctorReport(model, ENV));
    expect(text).not.toContain("secret-server-name");
    // But it DOES carry the redacted env + issue counts.
    expect(text).toContain("darwin arm64 24.5.0");
    expect(text).toContain("0.19.0");
    expect(text).toContain("secret store:    os-keychain");
    expect(text).toMatch(/1 missing-runtime/);
  });
});

describe("doctorHandler output modes (D7)", () => {
  it("--json emits the DoctorModel as parseable JSON", async () => {
    const lines: string[] = [];
    const code = await doctorHandler(
      fullDeps({ srv: { command: "npx", args: ["-y", "srv"] } }, () => true, (t) => lines.push(t)),
      { json: true }
    );
    const parsed = JSON.parse(lines.join("\n"));
    expect(parsed.schemaVersion).toBe(1);
    expect(Array.isArray(parsed.clients)).toBe(true);
    expect(parsed.ok).toBe(true);
    expect(code).toBe(0);
  });

  it("--report honors injected env and stays redacted", async () => {
    const lines: string[] = [];
    await doctorHandler(
      fullDeps({ "secret-server-name": { command: "uvx", args: ["x"] } }, (cmd) => cmd !== "uvx", (t) =>
        lines.push(t)
      ),
      { report: true, reportEnv: ENV }
    );
    const out = lines.join("\n");
    expect(out).not.toContain("secret-server-name");
    expect(out).toContain("secret store:    os-keychain");
  });
});

describe("handleDoctor MCP tool (D7 regression)", () => {
  it("returns the structured model instead of a hardcoded issues: []", async () => {
    // No config files exist → every client exists:false, no issues — but the shape
    // is now the real model (schemaVersion/ok), proving it reuses buildDoctorModel.
    const deps = {
      getAdapter: () => adapterFor({}),
      getConfigPath: (id: ClientId) => `/does/not/exist/${id}.json`,
    } as unknown as ServerDeps;

    const result = (await handleDoctor(deps)) as Record<string, unknown>;
    expect(result.schemaVersion).toBe(1);
    expect(result).toHaveProperty("ok");
    expect(Array.isArray(result.issues)).toBe(true);
    expect(Array.isArray(result.clients)).toBe(true);
  });
});
