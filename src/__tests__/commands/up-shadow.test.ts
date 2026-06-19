/**
 * Tests for the F2 cross-server tool-name-collision (shadow) pass in `mcpm up`.
 *
 * Covers:
 * - armed (option) + collision + interactive → ⚠ SHADOW warning, install proceeds (no throw)
 * - armed + collision + --ci → throws (the CI gate)
 * - NOT armed → detector never runs (readPins not called), no SHADOW output
 * - armed via policy.checkShadowing in the stack file → runs
 * - readPins throws (integrity/corruption) → "shadow check skipped", up still succeeds (fail-soft)
 * - coverage honesty line: "X of Y", and a loud no-baseline notice when a server has no pin
 * - no collision → coverage line present, no SHADOW warning, exit 0
 */

import { describe, it, expect, vi } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import type { PinsFile } from "../../guard/pins.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

function makeServerEntry(name: string, version: string): ServerEntry {
  return {
    server: {
      name,
      version,
      packages: [
        { registryType: "npm", identifier: `@test/${name.split("/").pop()}`, environmentVariables: [] },
      ],
    },
  };
}

const goodTrust: TrustScore = {
  score: 75,
  maxPossible: 80,
  level: "safe",
  breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
};

function makeAdapter(servers: Record<string, McpServerEntry> = {}) {
  return {
    clientId: "claude-desktop" as ClientId,
    read: vi.fn().mockResolvedValue({ ...servers }),
    addServer: vi.fn().mockResolvedValue(undefined),
    removeServer: vi.fn().mockResolvedValue(undefined),
    setServerDisabled: vi.fn().mockResolvedValue(undefined),
  };
}

function makeDeps(overrides: Partial<UpDeps> = {}): UpDeps {
  const adapter = makeAdapter();
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue(adapter),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    getServer: vi.fn().mockImplementation((name: string, version?: string) =>
      Promise.resolve(makeServerEntry(name, version ?? "1.0.0"))
    ),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(goodTrust),
    runLock: vi.fn().mockResolvedValue(undefined),
    confirm: vi.fn().mockResolvedValue(true),
    promptEnvVar: vi.fn().mockResolvedValue("v"),
    output: vi.fn(),
    fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

/** A PinsFile whose per-server records carry the given tool names as keys. */
function pinsOf(servers: Record<string, string[]>): PinsFile {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [name, tools] of Object.entries(servers)) {
    out[name] = Object.fromEntries(tools.map((t) => [t, { current_hash: null }]));
  }
  return { format_version: 1, servers: out } as unknown as PinsFile;
}

/** Two-server stack + lock. Optionally arms the shadow check via policy. */
async function writeTwoServerStack(opts: { policyCheckShadowing?: boolean } = {}): Promise<string> {
  const policyBlock = opts.policyCheckShadowing ? `policy:\n  checkShadowing: true\n` : "";
  const stack = `
version: "1"
${policyBlock}servers:
  alpha:
    version: "1.0.0"
  beta:
    version: "1.0.0"
`;
  const lockServer = (name: string): string => `  ${name}:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/${name}"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
  const lock = `lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
${lockServer("alpha")}${lockServer("beta")}`;
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-shadow-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stack, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lock, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

function collectOutput(deps: UpDeps): string {
  return (deps.output as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]).join("\n");
}

describe("handleUp — F2 shadow pass", () => {
  it("armed (option) + collision → ⚠ SHADOW warning, install still proceeds (no throw)", async () => {
    const stackPath = await writeTwoServerStack();
    const readPins = vi.fn().mockResolvedValue(pinsOf({ alpha: ["send_email"], beta: ["send_email", "list"] }));
    const deps = makeDeps({ readPins });

    await expect(handleUp({ stackFile: stackPath, checkShadowing: true }, deps)).resolves.toBeUndefined();

    const output = collectOutput(deps);
    expect(readPins).toHaveBeenCalledTimes(1);
    expect(output).toContain("SHADOW");
    expect(output).toContain("send_email");
    expect(output).toContain("alpha, beta"); // sorted owners
    expect(output).toMatch(/1 installed|2 installed/);
  });

  it("armed + collision + --ci → throws (CI gate)", async () => {
    const stackPath = await writeTwoServerStack();
    const deps = makeDeps({
      readPins: vi.fn().mockResolvedValue(pinsOf({ alpha: ["send_email"], beta: ["send_email"] })),
    });

    await expect(
      handleUp({ stackFile: stackPath, checkShadowing: true, ci: true, yes: true }, deps)
    ).rejects.toThrow(/collision/i);
  });

  it("NOT armed → detector never runs (readPins not called), no SHADOW output", async () => {
    const stackPath = await writeTwoServerStack();
    const readPins = vi.fn().mockResolvedValue(pinsOf({ alpha: ["send_email"], beta: ["send_email"] }));
    const deps = makeDeps({ readPins });

    await handleUp({ stackFile: stackPath }, deps); // no checkShadowing, no policy

    expect(readPins).not.toHaveBeenCalled();
    expect(collectOutput(deps)).not.toContain("SHADOW");
  });

  it("armed via policy.checkShadowing in the stack file → runs", async () => {
    const stackPath = await writeTwoServerStack({ policyCheckShadowing: true });
    const readPins = vi.fn().mockResolvedValue(pinsOf({ alpha: ["dup"], beta: ["dup"] }));
    const deps = makeDeps({ readPins });

    await handleUp({ stackFile: stackPath }, deps); // armed by policy, not option

    expect(readPins).toHaveBeenCalledTimes(1);
    expect(collectOutput(deps)).toContain('tool "dup"');
  });

  it("armed but no readPins dep wired → skip notice (not silent), no throw even under --ci", async () => {
    const stackPath = await writeTwoServerStack();
    const deps = makeDeps(); // makeDeps does NOT wire readPins

    await expect(
      handleUp({ stackFile: stackPath, checkShadowing: true, ci: true, yes: true }, deps)
    ).resolves.toBeUndefined();
    expect(collectOutput(deps)).toMatch(/shadow check skipped: no pins reader/i);
  });

  it("readPins throws (integrity/corruption) → 'shadow check skipped', up still succeeds (fail-soft)", async () => {
    const stackPath = await writeTwoServerStack();
    const deps = makeDeps({
      readPins: vi.fn().mockRejectedValue(new Error("pins integrity check failed")),
    });

    await expect(handleUp({ stackFile: stackPath, checkShadowing: true }, deps)).resolves.toBeUndefined();
    expect(collectOutput(deps)).toMatch(/shadow check skipped/i);
  });

  it("coverage honesty: reports 'X of Y' and a loud no-baseline notice", async () => {
    const stackPath = await writeTwoServerStack();
    // alpha is pinned; beta has never run under guard → no baseline.
    const deps = makeDeps({
      readPins: vi.fn().mockResolvedValue(pinsOf({ alpha: ["read_file"] })),
    });

    await handleUp({ stackFile: stackPath, checkShadowing: true }, deps);

    const output = collectOutput(deps);
    expect(output).toMatch(/compared guarded tool inventories for 1 of 2 server/);
    expect(output).toMatch(/NO guard baseline/);
    expect(output).toContain("beta");
    // Only one server contributed names → no collision possible.
    expect(output).not.toContain("⚠ SHADOW:");
  });

  it("no collision → coverage line present, no SHADOW warning, exit 0", async () => {
    const stackPath = await writeTwoServerStack();
    const deps = makeDeps({
      readPins: vi.fn().mockResolvedValue(pinsOf({ alpha: ["read_file"], beta: ["query"] })),
    });

    await expect(handleUp({ stackFile: stackPath, checkShadowing: true }, deps)).resolves.toBeUndefined();
    const output = collectOutput(deps);
    expect(output).toMatch(/Shadow check: compared guarded tool inventories for 2 of 2 server/);
    expect(output).not.toContain("⚠ SHADOW:");
  });
});
