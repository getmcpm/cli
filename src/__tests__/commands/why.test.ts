/**
 * Tests for src/commands/why.ts — the trust-score breakdown command.
 * All deps injected; no network, no scanner subprocess.
 */

import { describe, it, expect, vi } from "vitest";
import { handleWhy, type WhyDeps } from "../../commands/why.js";
import type { ServerEntry, EnvVar } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import { NotFoundError } from "../../registry/errors.js";

function makeServerEntry(over: Partial<ServerEntry["server"]> = {}): ServerEntry {
  return {
    server: {
      name: "io.github.test/srv",
      version: "1.0.0",
      description: "d",
      packages: [
        { registryType: "npm", identifier: "@test/srv", environmentVariables: [], runtimeArguments: [] },
      ],
      remotes: [],
      ...over,
    },
    _meta: {
      "io.modelcontextprotocol.registry/official": {
        status: "active",
        publishedAt: "2024-01-01T00:00:00Z",
        isLatest: true,
      },
    },
  } as ServerEntry;
}

function makeTrust(over: Partial<TrustScore> = {}): TrustScore {
  return {
    score: 72,
    maxPossible: 100,
    level: "caution",
    breakdown: { healthCheck: 15, staticScan: 40, externalScan: 10, registryMeta: 7 },
    ...over,
  };
}

function makeDeps(over: Partial<WhyDeps> = {}): WhyDeps {
  return {
    registryClient: { getServer: vi.fn().mockResolvedValue(makeServerEntry()) },
    scanTier1: vi.fn().mockReturnValue([] as Finding[]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([] as Finding[]),
    computeTrustScore: vi.fn().mockReturnValue(makeTrust()),
    output: vi.fn(),
    ...over,
  };
}

function out(deps: WhyDeps): string {
  return (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
}

describe("mcpm why", () => {
  it("renders score, level, and each component as earned/max", async () => {
    const deps = makeDeps();
    await handleWhy("io.github.test/srv", {}, deps);
    const o = out(deps);
    expect(o).toMatch(/72\/100/);
    expect(o).toMatch(/caution/);
    expect(o).toMatch(/Health check/);
    expect(o).toMatch(/15\/30/);
    expect(o).toMatch(/Static scan/);
    expect(o).toMatch(/40\/40/);
    expect(o).toMatch(/Registry meta/);
    expect(o).toMatch(/7\/10/);
  });

  it("lists findings with severity, type, message, and location", async () => {
    const findings: Finding[] = [
      { severity: "high", type: "secrets", message: "hardcoded key", location: "packages[0].description" },
    ];
    const deps = makeDeps({ scanTier1: vi.fn().mockReturnValue(findings) });
    await handleWhy("x", {}, deps);
    const o = out(deps);
    expect(o).toMatch(/Findings \(1\)/);
    expect(o).toMatch(/high/);
    expect(o).toMatch(/hardcoded key/);
    expect(o).toMatch(/packages\[0\]\.description/);
  });

  it("shows 'Findings: none' when clean", async () => {
    const deps = makeDeps();
    await handleWhy("x", {}, deps);
    expect(out(deps)).toMatch(/Findings: none/);
  });

  it("notes the registry-meta cap when a critical/high finding is present", async () => {
    const findings: Finding[] = [{ severity: "critical", type: "prompt-injection", message: "m", location: "l" }];
    const deps = makeDeps({ scanTier1: vi.fn().mockReturnValue(findings) });
    await handleWhy("x", {}, deps);
    expect(out(deps)).toMatch(/capped/i);
  });

  it("renders declared env vars with required/secret tags", async () => {
    const envs: EnvVar[] = [
      { name: "API_KEY", isRequired: true, isSecret: true },
      { name: "REGION", isRequired: false },
    ];
    const entry = makeServerEntry({
      packages: [{ registryType: "npm", identifier: "@test/srv", environmentVariables: envs, runtimeArguments: [] }],
    });
    const deps = makeDeps({ registryClient: { getServer: vi.fn().mockResolvedValue(entry) } });
    await handleWhy("x", {}, deps);
    const o = out(deps);
    expect(o).toMatch(/API_KEY/);
    expect(o).toMatch(/required/);
    expect(o).toMatch(/secret/);
    expect(o).toMatch(/REGION/);
  });

  it("merges tier2 findings when an external scanner is available", async () => {
    const deps = makeDeps({
      checkScannerAvailable: vi.fn().mockResolvedValue(true),
      scanTier1: vi.fn().mockReturnValue([{ severity: "low", type: "exfil-args", message: "t1", location: "a" }] as Finding[]),
      scanTier2: vi.fn().mockResolvedValue([{ severity: "medium", type: "secrets", message: "t2", location: "b" }] as Finding[]),
    });
    await handleWhy("srv", {}, deps);
    expect(deps.scanTier2).toHaveBeenCalledWith("srv");
    const o = out(deps);
    expect(o).toMatch(/t1/);
    expect(o).toMatch(/t2/);
  });

  it("--json emits a structured breakdown with values intact", async () => {
    const findings: Finding[] = [{ severity: "high", type: "secrets", message: "m", location: "l" }];
    const deps = makeDeps({ scanTier1: vi.fn().mockReturnValue(findings) });
    await handleWhy("x", { json: true }, deps);
    const parsed = JSON.parse(out(deps));
    expect(parsed).toMatchObject({
      name: "io.github.test/srv",
      score: 72,
      level: "caution",
      registryMetaCapped: true,
    });
    expect(parsed.breakdown.staticScan).toBe(40);
    expect(parsed.findings).toHaveLength(1);
  });

  it("handles a not-found server gracefully (no throw)", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockRejectedValue(new NotFoundError("ghost")) },
    });
    await expect(handleWhy("ghost", {}, deps)).resolves.toBeUndefined();
    expect(out(deps)).toMatch(/not found/);
  });
});
