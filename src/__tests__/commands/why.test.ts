/**
 * Tests for src/commands/why.ts — the trust-score breakdown command.
 * All deps injected; no network, no scanner subprocess.
 */

import { describe, it, expect, vi } from "vitest";
import { handleWhy, type WhyDeps } from "../../commands/why.js";
import type { ServerEntry, EnvVar } from "../../registry/types.js";
import { scanTier1 } from "../../scanner/tier1.js";
import type { Finding } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import { NotFoundError } from "../../registry/errors.js";
import type { NpmProvenanceSnapshot } from "../../registry/npm-provenance.js";

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

describe("mcpm why — release-age cooldown (F4)", () => {
  const NOW = new Date("2026-06-10T00:00:00Z").getTime();
  const FRESH_PUBLISHED_AT = new Date(NOW - 2 * 60 * 60 * 1000).toISOString();

  function makeFreshEntry(): ServerEntry {
    return {
      ...makeServerEntry(),
      _meta: {
        "io.modelcontextprotocol.registry/official": {
          status: "active",
          publishedAt: FRESH_PUBLISHED_AT,
          isLatest: true,
        },
      },
    } as ServerEntry;
  }

  it("renders the medium release-cooldown finding for a fresh release (human + --json)", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(makeFreshEntry()) },
      now: () => NOW,
    });
    await handleWhy("x", {}, deps);
    const o = out(deps);
    expect(o).toMatch(/\[medium\]/);
    expect(o).toMatch(/release-cooldown/);

    const jsonDeps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(makeFreshEntry()) },
      now: () => NOW,
    });
    await handleWhy("x", { json: true }, jsonDeps);
    const parsed = JSON.parse(out(jsonDeps));
    expect(
      parsed.findings.some(
        (f: Finding) => f.type === "release-cooldown" && f.severity === "medium"
      )
    ).toBe(true);
  });

  it("shows no release-cooldown finding when publishedAt is absent (score fail-open; why has no gate)", async () => {
    const entry = {
      server: {
        name: "io.github.test/clean-pypi",
        version: "1.0.0",
        description: "a plain server",
        packages: [
          { registryType: "pypi", identifier: "clean-pypi-server", environmentVariables: [], runtimeArguments: [] },
        ],
        remotes: [],
      },
      _meta: {},
    } as unknown as ServerEntry;
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(entry) },
      scanTier1,
      now: () => NOW,
    });
    await handleWhy("x", {}, deps);
    const o = out(deps);
    expect(o).toMatch(/Findings: none/);
    expect(o).not.toMatch(/release-cooldown/);
  });

  it("reflects the -5 static-scan deduction when the real computeTrustScore is injected", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(makeFreshEntry()) },
      computeTrustScore,
      now: () => NOW,
    });
    await handleWhy("x", {}, deps);
    expect(out(deps)).toMatch(/35\/40/);
  });
});

describe("mcpm why — F8 Provenance section", () => {
  const npmEntry = () =>
    makeServerEntry({
      packages: [{ registryType: "npm", identifier: "@test/srv", version: "1.0.0", environmentVariables: [], runtimeArguments: [] }],
    });
  const attestedSnap = (idOver: Partial<NpmProvenanceSnapshot["identity"]> = {}): NpmProvenanceSnapshot => ({
    npmVersion: "1.0.0", status: "attested", mode: "registry-record",
    identity: { sourceRepo: "https://github.com/a/b", repositoryId: "1", workflowPath: ".github/workflows/x.yml", commitSha: "abc123", ...idOver },
  });

  it("renders an attested Provenance section and NEVER says 'verified'", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(npmEntry()) },
      fetchNpmProvenance: vi.fn().mockResolvedValue(attestedSnap()),
    });
    await handleWhy("x", {}, deps);
    const o = out(deps);
    expect(deps.fetchNpmProvenance).toHaveBeenCalledWith("@test/srv", "1.0.0");
    expect(o).toContain("Provenance:");
    expect(o).toContain("attested");
    expect(o).toContain("github.com/a/b");
    // honesty boundary: never the standalone claim "verified" (the honest copy
    // says "unverified", which must NOT trip this).
    expect(o.toLowerCase()).not.toMatch(/\bverified\b/);
  });

  it("sanitizes ANSI/OSC in the (unverified) identity strings", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(npmEntry()) },
      fetchNpmProvenance: vi.fn().mockResolvedValue(attestedSnap({ sourceRepo: "https://github.com/a/b\u001b]0;pwn\u0007" })),
    });
    await handleWhy("x", {}, deps);
    // The attacker's OSC introducer (ESC + "]") must be gone; chalk's own
    // color codes use ESC + "[" (CSI), so assert specifically the OSC form.
    expect(out(deps)).not.toContain("\u001b]");
  });

  it("shows unsigned as explicitly neutral", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(npmEntry()) },
      fetchNpmProvenance: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" } as NpmProvenanceSnapshot),
    });
    await handleWhy("x", {}, deps);
    expect(out(deps)).toMatch(/unsigned.*neutral/i);
  });

  it("omits the section for a non-concrete version (fetch not called)", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(makeServerEntry()) }, // package has no version
      fetchNpmProvenance: vi.fn().mockResolvedValue(attestedSnap()),
    });
    await handleWhy("x", {}, deps);
    expect(deps.fetchNpmProvenance).not.toHaveBeenCalled();
    expect(out(deps)).not.toContain("Provenance:");
  });

  it("--json includes the provenance snapshot", async () => {
    const deps = makeDeps({
      registryClient: { getServer: vi.fn().mockResolvedValue(npmEntry()) },
      fetchNpmProvenance: vi.fn().mockResolvedValue(attestedSnap()),
    });
    await handleWhy("x", { json: true }, deps);
    expect(JSON.parse(out(deps)).provenance.status).toBe("attested");
  });
});
