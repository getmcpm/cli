/**
 * Tests for the F3 `up --frozen` fail-closed integrity BLOCK tier.
 *
 * Covers the block matrix + the load-bearing guarantees:
 * - drift / could-not-verify / format-only / mixed-missing-baseline → BLOCK (throws)
 * - PRE-install gating: on a block, the install loop never runs (getServer/addServer
 *   not called) so NOTHING is written
 * - all-integrity-equal → installs normally
 * - lock-wide-no-baseline (pre-H11 lock) → a distinct refuse-to-run, NOT a per-server verdict
 * - non-npm (pypi/oci) → coverage notice, never a block
 * - policy.frozen arms it without the flag; honesty boundary preserved
 */

import { describe, it, expect, vi } from "vitest";
import { handleUp } from "../../commands/up.js";
import type { UpDeps } from "../../commands/up.js";
import type { ClientId } from "../../config/paths.js";
import type { ServerEntry } from "../../registry/types.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import type { NpmIntegritySnapshot } from "../../registry/npm-integrity.js";
import type { NpmProvenanceSnapshot } from "../../stack/schema.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

const SRI_OLD = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
const SRI_NEW = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";

function makeServerEntry(name: string, version: string): ServerEntry {
  return {
    server: {
      name,
      version,
      packages: [{ registryType: "npm", identifier: `@test/${name.split("/").pop()}`, environmentVariables: [] }],
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

function trustBlock(): string {
  return `    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
}

/** A locked npm server, with or without an npmIntegrity baseline. */
function npmLock(name: string, integrity?: string): string {
  const baseline = integrity
    ? `    npmIntegrity:\n      npmVersion: "1.0.0"\n      integrity: "${integrity}"\n`
    : "";
  return `  ${name}:
    version: "1.0.0"
    registryType: npm
    identifier: "@test/${name}"
${trustBlock()}${baseline}`;
}

/** A locked pypi server (no integrity baseline mechanism exists). */
function pypiLock(name: string): string {
  return `  ${name}:
    version: "1.0.0"
    registryType: pypi
    identifier: "test-${name}"
${trustBlock()}`;
}

const PROV_ISSUER = "https://token.actions.githubusercontent.com";
const PROV_SAN = "https://github.com/acme/a/.github/workflows/publish.yml@refs/tags/v1.0.0";

/** A crypto-`verified` provenance snapshot YAML block (indented for a lock server). */
const VERIFIED_PROV_BLOCK = `    provenance:
      npmVersion: "1.0.0"
      status: attested
      mode: registry-record
      identity:
        sourceRepo: "https://github.com/acme/a"
      verification:
        outcome: verified
        signerSan: "${PROV_SAN}"
        signerIssuer: "${PROV_ISSUER}"
`;

/** A locked npm server whose lock recorded a crypto-`verified` provenance baseline. */
function verifiedNpmLock(name: string, integrity: string): string {
  return npmLock(name, integrity) + VERIFIED_PROV_BLOCK;
}

/** A verified provenance baseline with NO integrity baseline (sticky carry-forward shape). */
function verifiedProvNoIntegrityLock(name: string): string {
  return npmLock(name) + VERIFIED_PROV_BLOCK;
}

/** A provenance snapshot the fetchNpmProvenance mock returns on re-check. */
function freshProv(over: Record<string, unknown> = {}): NpmProvenanceSnapshot {
  return {
    npmVersion: "1.0.0",
    status: "attested",
    mode: "registry-record",
    identity: { sourceRepo: "https://github.com/acme/a" },
    verification: { outcome: "verified", signerSan: PROV_SAN, signerIssuer: PROV_ISSUER },
    ...over,
  } as NpmProvenanceSnapshot;
}

async function writeStackLock(serverNames: string[], lockBody: string): Promise<string> {
  const stack = `version: "1"\nservers:\n${serverNames.map((n) => `  ${n}:\n    version: "1.0.0"`).join("\n")}\n`;
  const lock = `lockfileVersion: 1\nlockedAt: "2026-04-05T10:00:00Z"\nservers:\n${lockBody}`;
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-frozen-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stack, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lock, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

function out(deps: UpDeps): string {
  return (deps.output as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0]).join("\n");
}

describe("handleUp — F3 --frozen BLOCK tier", () => {
  it("integrity drift → BLOCKS (throws) and installs NOTHING (pre-install gate)", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    // PROOF of pre-install gating: the install loop + backup never ran, so getServer
    // and getAdapter were never reached → nothing was resolved or written.
    expect(deps.getServer).not.toHaveBeenCalled();
    expect(deps.getAdapter).not.toHaveBeenCalled();
    expect(out(deps)).toMatch(/FROZEN.*changed since you locked it/i);
  });

  it("all integrity equal → frozen passes, install proceeds", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).resolves.toBeUndefined();
    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });

  it("could-not-verify → BLOCKS fail-closed with a distinct transient-aware message", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({ fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined) });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    const o = out(deps);
    expect(o).toMatch(/could not verify/i);
    expect(o).toMatch(/transient registry error/i); // distinct from deterministic drift
    expect(deps.getServer).not.toHaveBeenCalled();
  });

  it("format-only mismatch → BLOCKS fail-closed", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    expect(out(deps)).toMatch(/integrity format changed/i);
  });

  it("lock-wide-no-baseline (pre-H11 lock) → distinct refuse-to-run, NOT a poison verdict", async () => {
    const stackPath = await writeStackLock(["a", "b"], npmLock("a") + npmLock("b"));
    const fetchNpmIntegrity = vi.fn();
    const deps = makeDeps({ fetchNpmIntegrity });

    // The instruction lives in the thrown error (a refuse-to-run), not a per-server output line.
    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(
      /no integrity baselines.*online once/i
    );
    // It's a benign un-upgraded lock — never fetches and never emits a per-server "✗ FROZEN" verdict.
    expect(fetchNpmIntegrity).not.toHaveBeenCalled();
    expect(out(deps)).not.toMatch(/✗ FROZEN/);
  });

  it("mixed-lock gap (one npm server missing a baseline while another has one) → BLOCKS", async () => {
    const stackPath = await writeStackLock(["a", "b"], npmLock("a", SRI_OLD) + npmLock("b"));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    expect(out(deps)).toMatch(/no integrity baseline recorded for b/i);
  });

  it("non-npm (pypi) server → coverage notice, NOT a block; clean npm install proceeds", async () => {
    const stackPath = await writeStackLock(["a", "p"], npmLock("a", SRI_OLD) + pypiLock("p"));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).resolves.toBeUndefined();
    expect(out(deps)).toMatch(/server\(s\) \(pypi\/oci\/url\).*cannot enforce/i);
  });

  it("a pypi-ONLY lock (zero npm servers) → coverage notice, NOT a refuse-to-run; install proceeds", async () => {
    const stackPath = await writeStackLock(["p"], pypiLock("p"));
    const deps = makeDeps();
    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).resolves.toBeUndefined();
    expect(out(deps)).toMatch(/cannot enforce/i);
    // Must NOT hit the lock-wide-no-baseline refusal (that path is npm-only).
    expect(out(deps)).not.toMatch(/no integrity baselines/i);
  });

  it("policy.frozen arms the gate without the --frozen flag", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-up-frozen-pol-"));
    await writeFile(
      path.join(dir, "mcpm.yaml"),
      'version: "1"\npolicy:\n  frozen: true\nservers:\n  a:\n    version: "1.0.0"\n',
      "utf-8"
    );
    await writeFile(
      path.join(dir, "mcpm-lock.yaml"),
      `lockfileVersion: 1\nlockedAt: "2026-04-05T10:00:00Z"\nservers:\n${npmLock("a", SRI_OLD)}`,
      "utf-8"
    );
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });

    await expect(handleUp({ stackFile: path.join(dir, "mcpm.yaml") }, deps)).rejects.toThrow(/failed verification/i);
  });

  it("a frozen drift block under --dry-run STILL throws (it is a verification gate)", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });
    await expect(handleUp({ stackFile: stackPath, frozen: true, dryRun: true }, deps)).rejects.toThrow(/failed verification/i);
  });

  it("honesty boundary: block copy never over-claims it stopped the code", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });
    await handleUp({ stackFile: stackPath, frozen: true }, deps).catch(() => undefined);
    const o = out(deps);
    expect(o).toMatch(/published record/i);
    expect(o).toMatch(/not the code your agent runs/i);
    expect(o).not.toMatch(/different bytes|you are protected|blocked the attack|is safe|0%|100%/i);
  });

  it("frozen NOT armed → no integrity gate, normal install (no fetch-driven block)", async () => {
    const stackPath = await writeStackLock(["a"], npmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_NEW } as NpmIntegritySnapshot),
    });
    // Drift exists, but without --frozen it's WARN-only (post-install pass) and installs.
    await expect(handleUp({ stackFile: stackPath }, deps)).resolves.toBeUndefined();
    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });
});

describe("handleUp — F8/B3 --frozen provenance gate", () => {
  it("integrity clean but provenance REGRESSES → BLOCKS (throws), installs NOTHING", async () => {
    const stackPath = await writeStackLock(["a"], verifiedNpmLock("a", SRI_OLD));
    const deps = makeDeps({
      // integrity matches (no drift) — only provenance can block here.
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
      fetchNpmProvenance: vi
        .fn()
        .mockResolvedValue(freshProv({ verification: { outcome: "could-not-verify", reason: "tlog-fail" } })),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    expect(out(deps)).toMatch(/provenance for .* regressed/i);
    // Pre-install gate: nothing resolved or written.
    expect(deps.getServer).not.toHaveBeenCalled();
    expect(deps.getAdapter).not.toHaveBeenCalled();
  });

  it("provenance SIGNER changes → BLOCKS with a signer-swap message", async () => {
    const stackPath = await writeStackLock(["a"], verifiedNpmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
      fetchNpmProvenance: vi.fn().mockResolvedValue(
        freshProv({
          verification: {
            outcome: "verified",
            signerSan: "https://github.com/evil/a/.github/workflows/publish.yml@refs/tags/v1.0.0",
            signerIssuer: PROV_ISSUER,
          },
        })
      ),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    expect(out(deps)).toMatch(/cryptographic signer .* changed/i);
  });

  it("provenance re-verifies clean (same signer) → install proceeds", async () => {
    const stackPath = await writeStackLock(["a"], verifiedNpmLock("a", SRI_OLD));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
      fetchNpmProvenance: vi.fn().mockResolvedValue(freshProv()),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).resolves.toBeUndefined();
    const adapter = (deps.getAdapter as ReturnType<typeof vi.fn>).mock.results[0].value;
    expect(adapter.addServer).toHaveBeenCalledTimes(1);
  });

  it("noBaselines lock carrying a verified provenance regression → BLOCKS (not the benign refuse)", async () => {
    // Integrity is lock-wide-empty (no baseline), but a sticky verified provenance
    // baseline regressed — the block must NOT be hidden behind the benign refuse-to-run.
    const stackPath = await writeStackLock(["a"], verifiedProvNoIntegrityLock("a"));
    const deps = makeDeps({
      fetchNpmIntegrity: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", integrity: SRI_OLD } as NpmIntegritySnapshot),
      fetchNpmProvenance: vi
        .fn()
        .mockResolvedValue({ npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" }),
    });

    await expect(handleUp({ stackFile: stackPath, frozen: true }, deps)).rejects.toThrow(/failed verification/i);
    expect(out(deps)).toMatch(/provenance for .* regressed/i);
    // The integrity-gap notice is still shown (parallel to `mcpm verify`), not hidden.
    expect(out(deps)).toMatch(/no integrity baselines/i);
    // The benign "no integrity baselines" refuse must NOT be the thrown reason.
    expect(deps.getServer).not.toHaveBeenCalled();
  });
});
