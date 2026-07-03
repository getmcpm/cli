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
import type { LockFile, NpmIntegritySnapshot } from "../../stack/schema.js";

const SRI_OLD = "sha512-" + "A".repeat(86) + "==";
const SRI_NEW = "sha512-" + "B".repeat(86) + "==";

const TRUST = { score: 75, maxPossible: 80, level: "safe", assessedAt: "2026-04-05T10:00:00Z" };

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

function pypiEntry(identifier: string): Entry {
  return { version: "1.0.0", registryType: "pypi", identifier, trust: TRUST };
}

function lockOf(servers: Record<string, Entry>): LockFile {
  return { lockfileVersion: 1, lockedAt: "2026-04-05T10:00:00Z", servers } as unknown as LockFile;
}

function deps(
  lock: LockFile | null,
  fetch: (id: string, v: string) => Promise<NpmIntegritySnapshot | undefined>
): { deps: VerifyDeps; out: () => string; fetch: ReturnType<typeof vi.fn> } {
  const lines: string[] = [];
  const fetchMock = vi.fn(fetch);
  return {
    deps: {
      parseLock: vi.fn().mockResolvedValue(lock),
      fetchNpmIntegrity: fetchMock,
      output: (t: string) => lines.push(t),
    },
    out: () => lines.join("\n"),
    fetch: fetchMock,
  };
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
