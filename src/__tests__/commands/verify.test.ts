/**
 * D2 tests: `mcpm verify` — the repo-only, client-free lockfile integrity gate.
 *
 * verifyHandler injects parseLock + fetchNpmIntegrity, so the block matrix is
 * tested with in-memory locks (no temp files, no client detection). It mirrors the
 * up --frozen matrix because both consume the SAME shared frozenVerdict — here we
 * assert the verify-flavored verdict/model/exit-code, not up's install text.
 */

import { describe, it, expect, vi } from "vitest";
import { verifyHandler, type VerifyDeps, type VerifyModel } from "../../commands/verify.js";
import type {
  LockFile,
  NpmIntegritySnapshot,
  NpmProvenanceSnapshot,
  StackFile,
} from "../../stack/schema.js";

const SRI_OLD = "sha512-" + "A".repeat(86) + "==";
const SRI_NEW = "sha512-" + "B".repeat(86) + "==";

const TRUST = { score: 75, maxPossible: 80, level: "safe", assessedAt: "2026-04-05T10:00:00Z" };
const ISSUER = "https://token.actions.githubusercontent.com";
const SAN = "https://github.com/acme/a/.github/workflows/publish.yml@refs/tags/v1.0.0";

type Entry = Record<string, unknown>;

function npmEntry(identifier: string, integrity?: string): Entry {
  return {
    version: "1.0.0",
    registryType: "npm",
    identifier,
    trust: TRUST,
    ...(integrity ? { npmIntegrity: { npmVersion: "1.0.0", integrity } } : {}),
  };
}

/** An npm entry whose lock recorded a crypto-`verified` provenance baseline. */
function verifiedNpmEntry(identifier: string, integrity: string): Entry {
  return {
    ...npmEntry(identifier, integrity),
    provenance: {
      npmVersion: "1.0.0",
      status: "attested",
      mode: "registry-record",
      identity: { sourceRepo: "https://github.com/acme/a" },
      verification: { outcome: "verified", signerSan: SAN, signerIssuer: ISSUER },
    },
  };
}

const provSnap = (over: Partial<NpmProvenanceSnapshot> = {}): NpmProvenanceSnapshot => ({
  npmVersion: "1.0.0",
  status: "attested",
  mode: "registry-record",
  identity: { sourceRepo: "https://github.com/acme/a" },
  verification: { outcome: "verified", signerSan: SAN, signerIssuer: ISSUER },
  ...over,
});

function pypiEntry(identifier: string): Entry {
  return { version: "1.0.0", registryType: "pypi", identifier, trust: TRUST };
}

function lockOf(servers: Record<string, Entry>): LockFile {
  return { lockfileVersion: 1, lockedAt: "2026-04-05T10:00:00Z", servers } as unknown as LockFile;
}

function deps(
  lock: LockFile | null,
  fetch: (id: string, v: string) => Promise<NpmIntegritySnapshot | undefined>,
  fetchProv: (
    id: string,
    v: string,
    o: { integritySri: string }
  ) => Promise<NpmProvenanceSnapshot | undefined> = async () => undefined
): { deps: VerifyDeps; out: () => string; fetch: ReturnType<typeof vi.fn> } {
  const lines: string[] = [];
  const fetchMock = vi.fn(fetch);
  return {
    deps: {
      parseLock: vi.fn().mockResolvedValue(lock),
      // Default: no mcpm.yaml alongside the lock, so the coverage gate is skipped
      // and these cases exercise the integrity/provenance matrix alone.
      parseStack: vi.fn().mockResolvedValue(null),
      fetchNpmIntegrity: fetchMock,
      fetchNpmProvenance: vi.fn(fetchProv),
      output: (t: string) => lines.push(t),
    },
    out: () => lines.join("\n"),
    fetch: fetchMock,
  };
}

/** A stack file declaring `names`, with the shape verify's coverage gate reads. */
function stackOf(...names: string[]): StackFile {
  return {
    version: "1",
    servers: Object.fromEntries(names.map((n) => [n, { version: "1.0.0" }])),
  } as unknown as StackFile;
}

const snap = (integrity: string): NpmIntegritySnapshot =>
  ({ npmVersion: "1.0.0", integrity }) as NpmIntegritySnapshot;

describe("verifyHandler — block matrix", () => {
  it("all integrity equal → ok, exit 0, verified count", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_OLD));
    const code = await verifyHandler(d.deps);
    expect(code).toBe(0);
    expect(d.out()).toMatch(/✓ 1 npm server verified/);
  });

  it("integrity drift → BLOCK, exit 1", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_NEW));
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/integrity drift/i);
    expect(d.out()).toMatch(/verification failed: 1 server/);
  });

  it("could-not-verify (fetch returns undefined) → BLOCK, exit 1", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => undefined);
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/could not verify/i);
  });

  it("format-only mismatch (incomparable algorithms) → BLOCK, exit 1", async () => {
    const d = deps(
      lockOf({ a: npmEntry("@test/a", "sha1-" + "A".repeat(27) + "=") }),
      async () => snap(SRI_NEW)
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/integrity format changed/i);
  });

  it("lock-wide no baseline → benign refuse (exit 1), NEVER fetches", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a"), b: npmEntry("@test/b") }), async () => snap(SRI_OLD));
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/no integrity baselines/i);
    expect(d.fetch).not.toHaveBeenCalled();
  });

  it("mixed gap (one npm server has a baseline, another doesn't) → BLOCK, exit 1", async () => {
    const d = deps(
      lockOf({ a: npmEntry("@test/a", SRI_OLD), b: npmEntry("@test/b") }),
      async () => snap(SRI_OLD)
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/no integrity baseline recorded/i);
  });

  it("pypi-only lock → coverage notice, ok, exit 0 (never a refuse-to-run)", async () => {
    const d = deps(lockOf({ p: pypiEntry("test-p") }), async () => snap(SRI_OLD));
    const code = await verifyHandler(d.deps);
    expect(code).toBe(0);
    expect(d.out()).toMatch(/cannot enforce/i);
    expect(d.out()).not.toMatch(/no integrity baselines/i);
  });

  it("no lock file → exit 1 with a run-mcpm-lock message", async () => {
    const d = deps(null, async () => snap(SRI_OLD));
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/no lock file found.*mcpm lock/i);
  });

  it("fail-closed: a malformed lock (parseLock throws) → exit 1, never throws", async () => {
    const lines: string[] = [];
    const badDeps: VerifyDeps = {
      parseLock: vi.fn().mockRejectedValue(new Error("Invalid lock file (schema)")),
      parseStack: vi.fn().mockResolvedValue(null),
      fetchNpmIntegrity: vi.fn(),
      output: (t: string) => lines.push(t),
    };
    // Must resolve (not reject) to a non-zero code — the gate stays CLOSED on a bad lock.
    const code = await verifyHandler(badDeps, { json: true });
    expect(code).toBe(1);
    const model = JSON.parse(lines.join("\n")) as VerifyModel;
    expect(model.ok).toBe(false);
    expect(model.error).toMatch(/could not verify.*Invalid lock file/i);
  });
});

describe("verifyHandler — honesty + --json", () => {
  it("block copy never over-claims it stopped the code", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_NEW));
    await verifyHandler(d.deps);
    const o = d.out();
    expect(o).toMatch(/published record/i);
    expect(o).toMatch(/not the code your agent runs/i);
    expect(o).not.toMatch(/different bytes|you are protected|blocked the attack|is safe/i);
  });

  it("--json emits the structured model with the block classification", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_NEW));
    const code = await verifyHandler(d.deps, { json: true });
    expect(code).toBe(1);
    const model = JSON.parse(d.out()) as VerifyModel;
    expect(model.schemaVersion).toBe(1);
    expect(model.ok).toBe(false);
    expect(model.blocked).toHaveLength(1);
    expect(model.blocked[0]).toMatchObject({ name: "a", reason: "drift", identifier: "@test/a" });
  });

  it("--json on a clean lock reports ok + verified count", async () => {
    const d = deps(
      lockOf({ a: npmEntry("@test/a", SRI_OLD), b: npmEntry("@test/b", SRI_OLD) }),
      async () => snap(SRI_OLD)
    );
    const code = await verifyHandler(d.deps, { json: true });
    expect(code).toBe(0);
    const model = JSON.parse(d.out()) as VerifyModel;
    expect(model.ok).toBe(true);
    expect(model.verified).toBe(2);
    expect(model.checkedNpmCount).toBe(2);
  });
});

describe("verifyHandler — provenance gate (F8/B3)", () => {
  it("verified baseline that re-verifies with the same signer → ok, exit 0, re-verified line", async () => {
    const d = deps(
      lockOf({ a: verifiedNpmEntry("@test/a", SRI_OLD) }),
      async () => snap(SRI_OLD),
      async () => provSnap()
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(0);
    expect(d.out()).toMatch(/cryptographically re-verified/i);
  });

  it("verified baseline whose fresh attestation no longer verifies → BLOCK, exit 1", async () => {
    const d = deps(
      lockOf({ a: verifiedNpmEntry("@test/a", SRI_OLD) }),
      async () => snap(SRI_OLD),
      async () => provSnap({ verification: { outcome: "could-not-verify", reason: "tlog-fail" } })
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/provenance regressed/i);
    expect(d.out()).toMatch(/verification failed: 1 server/);
  });

  it("signer-changed → BLOCK, exit 1", async () => {
    const d = deps(
      lockOf({ a: verifiedNpmEntry("@test/a", SRI_OLD) }),
      async () => snap(SRI_OLD),
      async () =>
        provSnap({
          verification: {
            outcome: "verified",
            signerSan: "https://github.com/evil/a/.github/workflows/publish.yml@refs/tags/v1.0.0",
            signerIssuer: ISSUER,
          },
        })
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/signer identity changed/i);
  });

  it("integrity CLEAN but provenance regressed → still fails (both gates OR)", async () => {
    const d = deps(
      lockOf({ a: verifiedNpmEntry("@test/a", SRI_OLD) }),
      async () => snap(SRI_OLD), // integrity matches
      async () => undefined // provenance can't re-verify → unverifiable
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/could not cryptographically re-verify/i);
  });

  it("--json includes provenanceBlocked + checkedProvenanceCount", async () => {
    const d = deps(
      lockOf({ a: verifiedNpmEntry("@test/a", SRI_OLD) }),
      async () => snap(SRI_OLD),
      async () => ({ npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" })
    );
    const code = await verifyHandler(d.deps, { json: true });
    expect(code).toBe(1);
    const model = JSON.parse(d.out()) as VerifyModel;
    expect(model.checkedProvenanceCount).toBe(1);
    expect(model.provenanceBlocked).toHaveLength(1);
    expect(model.provenanceBlocked[0]).toMatchObject({ name: "a", reason: "regression" });
  });

  it("a lock with NO verified baseline is provenance-silent (evidence-gated)", async () => {
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_OLD));
    const code = await verifyHandler(d.deps, { json: true });
    expect(code).toBe(0);
    const model = JSON.parse(d.out()) as VerifyModel;
    expect(model.checkedProvenanceCount).toBe(0);
    expect(model.provenanceBlocked).toEqual([]);
  });

  it("noBaselines lock that ALSO carries a regressed verified baseline → block is NOT hidden, exit 1", async () => {
    // A verified provenance baseline with NO npmIntegrity baseline (the sticky
    // carry-forward shape): integrity is noBaselines, but provenance still regresses.
    const provOnly: Entry = {
      version: "1.0.0",
      registryType: "npm",
      identifier: "@test/a",
      trust: TRUST,
      provenance: {
        npmVersion: "1.0.0",
        status: "attested",
        mode: "registry-record",
        identity: { sourceRepo: "https://github.com/acme/a" },
        verification: { outcome: "verified", signerSan: SAN, signerIssuer: ISSUER },
      },
    };
    const d = deps(
      lockOf({ a: provOnly }),
      async () => snap(SRI_OLD),
      async () => ({ npmVersion: "1.0.0", status: "unsigned", mode: "registry-record" })
    );
    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/no integrity baselines/i); // benign note still shown
    expect(d.out()).toMatch(/provenance regressed/i); // but the real block is NOT hidden behind it
  });
});

// ---------------------------------------------------------------------------
// Lock coverage — the lock must account for every server the stack declares
// ---------------------------------------------------------------------------

describe("verifyHandler — lock coverage gate", () => {
  it("empty lock + declared servers → BLOCK, exit 1", async () => {
    // The headline fail-open: `mcpm lock` could leave `servers: {}` on disk, and
    // verify then reported "✓ 0 npm servers verified" with ok:true / exit 0.
    // Both gates pass VACUOUSLY over an empty server set, so nothing caught it.
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("io.github.test/a", "io.github.test/b"));

    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/missing from the lock/i);
    expect(d.out()).toMatch(/io\.github\.test\/a/);
    expect(d.out()).toMatch(/io\.github\.test\/b/);
  });

  it("lock missing ONE declared server → BLOCK, exit 1", async () => {
    // Truncation, not emptiness: 2 declared, 1 locked. The locked one verifies
    // fine, so every existing gate is green — only coverage catches this.
    const d = deps(lockOf({ "io.github.test/a": npmEntry("@test/a", SRI_OLD) }), async () =>
      snap(SRI_OLD)
    );
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("io.github.test/a", "io.github.test/b"));

    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/io\.github\.test\/b/);
  });

  it("lock covers every declared server → ok, exit 0", async () => {
    const d = deps(lockOf({ "io.github.test/a": npmEntry("@test/a", SRI_OLD) }), async () =>
      snap(SRI_OLD)
    );
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("io.github.test/a"));

    expect(await verifyHandler(d.deps)).toBe(0);
  });

  it("a stack declaring nothing is covered by an empty lock → ok, exit 0", async () => {
    // No false positive on a fresh `mcpm init` project: nothing was asked for, so
    // nothing is missing. Emptiness alone is not the defect — a GAP is.
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf());

    expect(await verifyHandler(d.deps)).toBe(0);
  });

  it("extra servers in the lock are not a coverage failure", async () => {
    // A stale entry left in the lock is not the direction that matters — it can
    // only add verification, never remove it.
    const d = deps(
      lockOf({
        "io.github.test/a": npmEntry("@test/a", SRI_OLD),
        "io.github.test/stale": npmEntry("@test/stale", SRI_OLD),
      }),
      async () => snap(SRI_OLD)
    );
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("io.github.test/a"));

    expect(await verifyHandler(d.deps)).toBe(0);
  });

  it("no stack file → coverage skipped, lock verified on its own terms", async () => {
    // verify's contract is lock-first; mcpm.yaml is not required to be present.
    const d = deps(lockOf({ a: npmEntry("@test/a", SRI_OLD) }), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(null);

    expect(await verifyHandler(d.deps)).toBe(0);
  });

  it("reports uncovered servers under --json", async () => {
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("io.github.test/a"));

    const code = await verifyHandler(d.deps, { json: true });
    expect(code).toBe(1);
    const model = JSON.parse(d.out()) as VerifyModel;
    expect(model.ok).toBe(false);
    expect(model.uncovered).toEqual(["io.github.test/a"]);
  });
});

describe("verifyHandler — vacuous lock", () => {
  it("empty lock + NO stack file → BLOCK, exit 1 (cannot confirm it is intentional)", async () => {
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(null);

    const code = await verifyHandler(d.deps);
    expect(code).toBe(1);
    expect(d.out()).toMatch(/contains no servers/i);
    // The misleading green line must be gone, not merely outranked.
    expect(d.out()).not.toMatch(/✓ 0 npm servers verified/);
  });

  it("empty lock + a stack declaring nothing → ok, exit 0", async () => {
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf());

    const code = await verifyHandler(d.deps);
    expect(code).toBe(0);
    expect(d.out()).not.toMatch(/contains no servers/i);
  });

  it("never claims a ✓ for zero verified servers", async () => {
    // pypi-only: nothing npm to check, but the lock is NOT empty — no vacuous block,
    // and no "✓ 0 ... verified" either.
    const d = deps(lockOf({ p: pypiEntry("test-p") }), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(stackOf("p"));

    expect(await verifyHandler(d.deps)).toBe(0);
    expect(d.out()).toMatch(/cannot enforce/i);
    expect(d.out()).not.toMatch(/✓ 0 npm/);
  });
});

describe("verifyHandler — report never contradicts itself", () => {
  it("a vacuous lock does not ALSO claim the stack declares no servers", async () => {
    // There is no stack file in this case — asserting anything about what it
    // declares would be a fabrication sitting directly under the ✗.
    const d = deps(lockOf({}), async () => snap(SRI_OLD));
    d.deps.parseStack = vi.fn().mockResolvedValue(null);

    await verifyHandler(d.deps);
    expect(d.out()).toMatch(/contains no servers/i);
    expect(d.out()).not.toMatch(/this stack declares no servers/i);
  });
});
