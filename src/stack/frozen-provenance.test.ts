/**
 * Unit tests for the F8/B3 provenance verify-time gate (classifyProvenance).
 *
 * Focus: the EVIDENCE-GATING (only crypto-`verified` baselines are checked) and the
 * per-server regression classification (signer-changed / regression / unverifiable),
 * plus the fail-closed handling of every fresh-fetch outcome.
 */

import { describe, it, expect, vi } from "vitest";
import { classifyProvenance, type FetchNpmProvenance } from "./frozen-provenance.js";
import { memoizeIntegrity, type FetchNpmIntegrity } from "./frozen-verify.js";
import type { LockFile, NpmProvenanceSnapshot, TrustSnapshot } from "./schema.js";

const ISSUER = "https://token.actions.githubusercontent.com";
const SAN = "https://github.com/acme/pkg/.github/workflows/publish.yml@refs/tags/v1.0.0";
const SRI = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

const TRUST: TrustSnapshot = {
  score: 90,
  maxPossible: 100,
  level: "safe",
  assessedAt: "2026-01-01T00:00:00.000Z",
};

/** A locked npm server carrying an arbitrary provenance snapshot. */
function npmServer(identifier: string, provenance?: NpmProvenanceSnapshot) {
  return {
    version: "1.0.0",
    registryType: "npm",
    identifier,
    trust: TRUST,
    npmIntegrity: { npmVersion: "1.0.0", integrity: SRI },
    ...(provenance !== undefined ? { provenance } : {}),
  };
}

/** A snapshot recorded as cryptographically verified at lock time (the gated case). */
function verifiedSnapshot(over: Partial<NpmProvenanceSnapshot> = {}): NpmProvenanceSnapshot {
  return {
    npmVersion: "1.0.0",
    status: "attested",
    mode: "registry-record",
    identity: { sourceRepo: "https://github.com/acme/pkg" },
    verification: { outcome: "verified", signerSan: SAN, signerIssuer: ISSUER },
    ...over,
  };
}

function lockOf(servers: Record<string, ReturnType<typeof npmServer>>): LockFile {
  return { lockfileVersion: 1, lockedAt: "2026-01-01T00:00:00.000Z", servers };
}

/** integrity fetcher that always resolves the same SRI (the non-drift case). */
const integrityOk: FetchNpmIntegrity = vi.fn(async (_id, npmVersion) => ({
  npmVersion,
  integrity: SRI,
}));

/** provenance fetcher returning a fixed snapshot (per test). */
function provenanceReturning(snap: NpmProvenanceSnapshot | undefined): FetchNpmProvenance {
  return vi.fn(async () => snap);
}

describe("classifyProvenance — evidence gating", () => {
  it("checks NOTHING when no server has a crypto-verified baseline", async () => {
    const prov = provenanceReturning(verifiedSnapshot());
    const integ = vi.fn(integrityOk);
    const lock = lockOf({
      // attested-only (no verification block) — not gated
      a: npmServer("a-pkg", { npmVersion: "1.0.0", status: "attested", mode: "registry-record" }),
      // could-not-verify baseline — not gated (never asserted verified)
      b: npmServer("b-pkg", verifiedSnapshot({ verification: { outcome: "could-not-verify" } })),
      // unsigned — not gated
      c: npmServer("c-pkg", { npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" }),
      // no provenance at all (pre-F8 lock) — not gated
      d: npmServer("d-pkg"),
    });

    const verdict = await classifyProvenance(lock, integ, prov);

    expect(verdict.ok).toBe(true);
    expect(verdict.blocks).toEqual([]);
    expect(verdict.checkedVerifiedCount).toBe(0);
    // Evidence-gating: neither fetcher is invoked when nothing qualifies.
    expect(integ).not.toHaveBeenCalled();
    expect(prov).not.toHaveBeenCalled();
  });

  it("ignores non-npm registry servers even if they carry a verified snapshot", async () => {
    const prov = provenanceReturning(verifiedSnapshot());
    const pypi = { ...npmServer("pypi-pkg", verifiedSnapshot()), registryType: "pypi" };
    const verdict = await classifyProvenance(lockOf({ p: pypi }), vi.fn(integrityOk), prov);
    expect(verdict.checkedVerifiedCount).toBe(0);
    expect(prov).not.toHaveBeenCalled();
  });
});

describe("classifyProvenance — PASS", () => {
  it("passes when the fresh re-verify still verifies with the SAME signer", async () => {
    const prov = provenanceReturning(verifiedSnapshot());
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      prov
    );
    expect(verdict.ok).toBe(true);
    expect(verdict.blocks).toEqual([]);
    expect(verdict.checkedVerifiedCount).toBe(1);
  });

  it("binds the crypto re-verify to the CURRENT integrity, not the locked baseline", async () => {
    const integ = vi.fn(integrityOk);
    const prov = vi.fn(async () => verifiedSnapshot());
    await classifyProvenance(lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }), integ, prov);
    // fetchNpmProvenance must receive the FRESHLY-fetched SRI as integritySri.
    expect(prov).toHaveBeenCalledWith("a-pkg", "1.0.0", { integritySri: SRI });
  });
});

describe("classifyProvenance — signer-changed", () => {
  it("blocks when the fresh attestation verifies under a DIFFERENT signer SAN", async () => {
    const fresh = verifiedSnapshot({
      verification: {
        outcome: "verified",
        signerSan: "https://github.com/evil/pkg/.github/workflows/publish.yml@refs/tags/v1.0.0",
        signerIssuer: ISSUER,
      },
    });
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.blocks[0]?.reason).toBe("signer-changed");
    expect(verdict.blocks[0]?.detail).toContain("evil");
  });

  it("blocks when the fresh signer ISSUER differs, and the detail names the ISSUER (not a bogus SAN X→X)", async () => {
    const fresh = verifiedSnapshot({
      verification: { outcome: "verified", signerSan: SAN, signerIssuer: "https://evil.example/oidc" },
    });
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.blocks[0]?.reason).toBe("signer-changed");
    expect(verdict.blocks[0]?.detail).toContain("issuer");
    // SAN is identical → must NOT print a "SAN X → X" delta.
    expect(verdict.blocks[0]?.detail).not.toContain(`SAN ${SAN} → ${SAN}`);
  });
});

describe("classifyProvenance — regression", () => {
  it("blocks when the attestation is GONE (fresh 404 → unsigned) for a pinned coordinate", async () => {
    const fresh: NpmProvenanceSnapshot = { npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" };
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.blocks[0]?.reason).toBe("regression");
    expect(verdict.blocks[0]?.detail).toContain("unsigned");
  });

  it("blocks when the fresh bundle no longer cryptographically verifies", async () => {
    const fresh = verifiedSnapshot({
      verification: { outcome: "could-not-verify", reason: "subject-digest-mismatch" },
    });
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.blocks[0]?.reason).toBe("regression");
    expect(verdict.blocks[0]?.detail).toContain("subject-digest-mismatch");
  });
});

describe("classifyProvenance — unverifiable (fail-closed, re-run)", () => {
  it("blocks when the fresh fetch fails open (undefined — offline/endpoint error)", async () => {
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(undefined)
    );
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
  });

  it("blocks when the fresh record is an unrecognizable SLSA shape (unsupported)", async () => {
    const fresh: NpmProvenanceSnapshot = { npmVersion: "1.0.0", status: "unsupported", mode: "registry-record" };
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
  });

  it("blocks when the fresh attestation is present but crypto did not run (no verification block)", async () => {
    const fresh = verifiedSnapshot({ verification: undefined });
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      vi.fn(integrityOk),
      provenanceReturning(fresh)
    );
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
  });

  it("blocks when CURRENT integrity cannot be fetched (can't bind the attestation)", async () => {
    const integ = vi.fn(async () => undefined);
    const prov = vi.fn(async () => verifiedSnapshot());
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      integ,
      prov
    );
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
    // Without integrity to bind against, we must NOT even attempt the crypto re-verify.
    expect(prov).not.toHaveBeenCalled();
  });

  it("does NOT vacuously PASS when both baseline and fresh verification lack a signer SAN", async () => {
    // Baseline recorded verified but WITHOUT a signerSan (hand-crafted/corrupted lock).
    const lock = lockOf({
      a: npmServer("a-pkg", verifiedSnapshot({ verification: { outcome: "verified" } })),
    });
    // Fresh also verifies with no SAN — undefined===undefined would vacuously pass.
    const fresh = verifiedSnapshot({ verification: { outcome: "verified" } });
    const verdict = await classifyProvenance(lock, vi.fn(integrityOk), provenanceReturning(fresh));
    expect(verdict.ok).toBe(false);
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
  });

  it("never throws — a fetcher that THROWS fails CLOSED (unverifiable), not open", async () => {
    const integ = vi.fn(async () => {
      throw new Error("boom");
    });
    const verdict = await classifyProvenance(
      lockOf({ a: npmServer("a-pkg", verifiedSnapshot()) }),
      integ,
      provenanceReturning(verifiedSnapshot())
    );
    expect(verdict.ok).toBe(false);
    expect(verdict.blocks[0]?.reason).toBe("unverifiable");
  });
});

describe("memoizeIntegrity", () => {
  it("dedupes CONCURRENT calls for the same coordinate to ONE underlying fetch", async () => {
    let calls = 0;
    const slow: FetchNpmIntegrity = vi.fn(async (_id, v) => {
      calls++;
      await Promise.resolve();
      return { npmVersion: v, integrity: SRI };
    });
    const memo = memoizeIntegrity(slow);
    // both gates fire concurrently for the same coordinate.
    const [a, b] = await Promise.all([memo("pkg", "1.0.0"), memo("pkg", "1.0.0")]);
    expect(calls).toBe(1);
    expect(a).toEqual(b);
  });

  it("keys on identifier AND version — distinct coordinates each fetch", async () => {
    const fetch: FetchNpmIntegrity = vi.fn(async (_id, v) => ({ npmVersion: v, integrity: SRI }));
    const memo = memoizeIntegrity(fetch);
    await Promise.all([memo("a", "1.0.0"), memo("a", "2.0.0"), memo("b", "1.0.0")]);
    expect(fetch).toHaveBeenCalledTimes(3);
  });
});

describe("classifyProvenance — multiple servers", () => {
  it("classifies each verified server independently and counts the checked set", async () => {
    const integ = vi.fn(integrityOk);
    // per-identifier fresh result
    const prov: FetchNpmProvenance = vi.fn(async (id) => {
      if (id === "good-pkg") return verifiedSnapshot();
      if (id === "gone-pkg") return { npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" };
      return undefined; // offline-pkg
    });
    const lock = lockOf({
      good: npmServer("good-pkg", verifiedSnapshot()),
      gone: npmServer("gone-pkg", verifiedSnapshot()),
      offline: npmServer("offline-pkg", verifiedSnapshot()),
      unsigned: npmServer("plain-pkg", { npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" }),
    });

    const verdict = await classifyProvenance(lock, integ, prov);

    expect(verdict.checkedVerifiedCount).toBe(3); // good + gone + offline (NOT the unsigned one)
    expect(verdict.ok).toBe(false);
    const byName = Object.fromEntries(verdict.blocks.map((b) => [b.name, b.reason]));
    expect(byName).toEqual({ gone: "regression", offline: "unverifiable" });
  });
});
