/**
 * Tests for npm provenance snapshot capture + identity-drift reporting in
 * `mcpm lock` (F8 slice 1 — parse-only, report-only).
 */

import { describe, it, expect, vi } from "vitest";
import { handleLock } from "../../commands/lock.js";
import type { LockDeps } from "../../commands/lock.js";
import type { ServerEntry } from "../../registry/types.js";
import type { NpmProvenanceSnapshot } from "../../registry/npm-provenance.js";
import type { LockFile } from "../../stack/schema.js";
import type { TrustScore } from "../../scanner/trust-score.js";
import { parse as parseYaml } from "yaml";
import { LockFileSchema } from "../../stack/schema.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

const SERVER = "io.github.test/my-server";

function entry(pkgVersion = "1.0.0", registryType = "npm"): ServerEntry {
  return {
    server: {
      name: SERVER,
      version: "1.0.0",
      packages: [{ registryType, identifier: "@test/my-server", version: pkgVersion, environmentVariables: [] }],
    },
  };
}

const trustScore: TrustScore = {
  score: 75, maxPossible: 80, level: "safe",
  breakdown: { healthCheck: 15, staticScan: 40, externalScan: 0, registryMeta: 10 },
};

const attested = (id: string, owner = "9", repo = "https://github.com/a/b"): NpmProvenanceSnapshot => ({
  npmVersion: "1.0.0", status: "attested", mode: "registry-record",
  identity: { repositoryId: id, repositoryOwnerId: owner, sourceRepo: repo },
});

function prevLockWith(prov: NpmProvenanceSnapshot): LockFile {
  return {
    lockfileVersion: 1,
    lockedAt: "2026-01-01T00:00:00Z",
    servers: {
      [SERVER]: {
        version: "1.0.0", registryType: "npm", identifier: "@test/my-server",
        trust: { score: 75, maxPossible: 80, level: "safe", assessedAt: "2026-01-01T00:00:00Z" },
        provenance: prov,
      },
    },
  };
}

async function writeTempStack(): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-lock-prov-test-"));
  const filePath = path.join(dir, "mcpm.yaml");
  await writeFile(filePath, `version: "1"\nservers:\n  ${SERVER}:\n    version: "1.0.0"\n`, "utf-8");
  return filePath;
}

function makeDeps(serverEntry: ServerEntry, overrides: Partial<LockDeps> = {}): LockDeps {
  return {
    getServerVersions: vi.fn().mockResolvedValue([{ version: "1.0.0" }]),
    getServer: vi.fn().mockResolvedValue(serverEntry),
    scanTier1: vi.fn().mockReturnValue([]),
    checkScannerAvailable: vi.fn().mockResolvedValue(false),
    scanTier2: vi.fn().mockResolvedValue([]),
    computeTrustScore: vi.fn().mockReturnValue(trustScore),
    writeLockFile: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    fetchNpmIntegrity: vi.fn().mockResolvedValue(undefined),
    fetchNpmProvenance: vi.fn().mockResolvedValue(attested("1")),
    readExistingLock: vi.fn().mockResolvedValue(null),
    ...overrides,
  };
}

function lockedFromWrite(deps: LockDeps): Record<string, unknown> {
  const [, content] = (deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0];
  return parseYaml(content).servers[SERVER];
}
function outputText(deps: LockDeps): string {
  return (deps.output as ReturnType<typeof vi.fn>).mock.calls.flat().join("\n");
}

describe("handleLock — provenance capture", () => {
  it("captures the provenance snapshot for a concrete npm coordinate", async () => {
    const deps = makeDeps(entry());
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(deps.fetchNpmProvenance).toHaveBeenCalledWith("@test/my-server", "1.0.0", undefined);
    const locked = lockedFromWrite(deps);
    expect((locked as { provenance?: NpmProvenanceSnapshot }).provenance?.status).toBe("attested");
    expect(LockFileSchema.safeParse(parseYaml((deps.writeLockFile as ReturnType<typeof vi.fn>).mock.calls[0][1])).success).toBe(true);
  });

  it("does NOT capture provenance for a non-concrete version (gate shared with integrity)", async () => {
    const deps = makeDeps(entry("^1.0.0"));
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(deps.fetchNpmProvenance).not.toHaveBeenCalled();
    expect((lockedFromWrite(deps) as { provenance?: unknown }).provenance).toBeUndefined();
  });

  it("fail-open: provenance undefined → block omitted, lock still succeeds", async () => {
    const deps = makeDeps(entry(), { fetchNpmProvenance: vi.fn().mockResolvedValue(undefined) });
    await expect(handleLock({ stackFile: await writeTempStack() }, deps)).resolves.toBeUndefined();
    expect((lockedFromWrite(deps) as { provenance?: unknown }).provenance).toBeUndefined();
  });
});

describe("handleLock — provenance-identity drift (report-only)", () => {
  it("WARNs on a changed repo/owner id vs the previous lock — and still writes the lock", async () => {
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("2", "9", "https://github.com/x/y")),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(attested("1", "9", "https://github.com/a/b"))),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(outputText(deps)).toContain("provenance identity changed");
    expect(outputText(deps)).toContain("github.com/a/b");
    expect(outputText(deps)).toContain("github.com/x/y");
    expect(deps.writeLockFile).toHaveBeenCalledTimes(1); // report-only: never blocks the write
  });

  it("WARNs on a signed→unsigned drop", async () => {
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue({ npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" } as NpmProvenanceSnapshot),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(attested("1"))),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(outputText(deps)).toContain("provenance dropped");
  });

  it("no baseline (no previous lock) → silent, no drift noise", async () => {
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("2")),
      readExistingLock: vi.fn().mockResolvedValue(null),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(outputText(deps)).not.toContain("provenance");
  });

  it("stable identity across versions → no drift warning", async () => {
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("1")),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(attested("1"))),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(outputText(deps)).not.toContain("provenance");
  });

  it("carries a known-good baseline forward through a transient fetch failure (same version)", async () => {
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(undefined), // fail-open this run
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(attested("1"))),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    const locked = lockedFromWrite(deps) as { provenance?: NpmProvenanceSnapshot };
    // baseline preserved (NOT erased → the tripwire stays armed for the next run)
    expect(locked.provenance?.status).toBe("attested");
    expect(locked.provenance?.identity?.repositoryId).toBe("1");
    expect(outputText(deps)).not.toContain("provenance"); // transient failure = no drift noise
  });

  it("carries a VERIFIED baseline forward when crypto didn't run this re-lock (attested-without-verification)", async () => {
    // Fresh snapshot is attested but has NO verification block (integrity blipped, or
    // @sigstore failed to load) — this must NOT downgrade a prior crypto-`verified`
    // baseline, or the F8 verify-time tripwire silently disarms for that server.
    const verifiedProv: NpmProvenanceSnapshot = {
      ...attested("1"),
      verification: {
        outcome: "verified",
        signerSan: "https://github.com/a/b/.github/workflows/x.yml@refs/tags/v1",
        signerIssuer: "https://token.actions.githubusercontent.com",
      },
    };
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("1")), // attested, verification ABSENT
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(verifiedProv)),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    const locked = lockedFromWrite(deps) as { provenance?: NpmProvenanceSnapshot };
    expect(locked.provenance?.verification?.outcome).toBe("verified"); // preserved, not downgraded
  });

  it("carries a VERIFIED baseline forward + WARNS when crypto RAN and FAILED this re-lock (could-not-verify)", async () => {
    // The common regression/attack shape: crypto ran and returned could-not-verify (a
    // PRESENT verification block), not verification===undefined. Must NOT disarm the gate.
    const verifiedProv: NpmProvenanceSnapshot = {
      ...attested("1"),
      verification: { outcome: "verified", signerSan: "https://github.com/a/b/.github/workflows/x.yml@refs/tags/v1", signerIssuer: "https://token.actions.githubusercontent.com" },
    };
    const freshFailed: NpmProvenanceSnapshot = {
      ...attested("1"), // SAME identity as the baseline
      verification: { outcome: "could-not-verify", reason: "subject-digest-mismatch" },
    };
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(freshFailed),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(verifiedProv)),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    const locked = lockedFromWrite(deps) as { provenance?: NpmProvenanceSnapshot };
    expect(locked.provenance?.verification?.outcome).toBe("verified"); // baseline preserved, gate stays armed
    expect(outputText(deps)).toMatch(/verification regressed/i); // and loudly warned
  });

  it("does NOT carry a could-not-verify with a DIFFERENT identity — surfaces the swap (hard, same-version copy)", async () => {
    const verifiedProv: NpmProvenanceSnapshot = {
      ...attested("1"),
      verification: { outcome: "verified", signerSan: "https://github.com/a/b/.github/workflows/x.yml@refs/tags/v1", signerIssuer: "https://token.actions.githubusercontent.com" },
    };
    const freshDifferent: NpmProvenanceSnapshot = {
      ...attested("2", "9", "https://github.com/evil/pkg"), // DIFFERENT repositoryId
      verification: { outcome: "could-not-verify", reason: "subject-digest-mismatch" },
    };
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(freshDifferent),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(verifiedProv)),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    const locked = lockedFromWrite(deps) as { provenance?: NpmProvenanceSnapshot };
    // Not carried → the fresh (different-identity) snapshot overwrites.
    expect(locked.provenance?.verification?.outcome).not.toBe("verified");
    // Same immutable version → HARD swap copy, not the org-transfer hedge.
    expect(outputText(deps)).toMatch(/SAME version|attestation swap/i);
  });

  it("does NOT carry the verified baseline across an identifier swap (different package, same name+version)", async () => {
    const verifiedProv: NpmProvenanceSnapshot = {
      ...attested("1"),
      verification: { outcome: "verified", signerSan: "https://github.com/a/b/.github/workflows/x.yml@refs/tags/v1", signerIssuer: "https://token.actions.githubusercontent.com" },
    };
    // Server entry now resolves a DIFFERENT npm identifier under the same server name.
    const swapped: ServerEntry = {
      server: { name: SERVER, version: "1.0.0", packages: [{ registryType: "npm", identifier: "@rival/other", version: "1.0.0", environmentVariables: [] }] },
    };
    const deps = makeDeps(swapped, {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("1")), // fresh attested-no-verification for the NEW pkg
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(verifiedProv)), // prev verified for @test/my-server
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    const locked = lockedFromWrite(deps) as { provenance?: NpmProvenanceSnapshot };
    // The prior verified baseline must NOT ride onto the swapped package.
    expect(locked.provenance?.verification).toBeUndefined();
  });

  it("sanitizes ANSI/OSC in a drift warning's repo label (warning can't become an injection carrier)", async () => {
    const evil = "https://github.com/a/b\u001b]0;pwn\u0007\u001b[2K";
    const deps = makeDeps(entry(), {
      fetchNpmProvenance: vi.fn().mockResolvedValue(attested("2", "9", "https://github.com/x/y")),
      readExistingLock: vi.fn().mockResolvedValue(prevLockWith(attested("1", "9", evil))),
    });
    await handleLock({ stackFile: await writeTempStack() }, deps);
    expect(outputText(deps)).toContain("provenance identity changed");
    expect(outputText(deps)).not.toContain("\u001b"); // escapes stripped
  });
});
