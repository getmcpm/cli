/**
 * Shared lockfile integrity verification (F3 / D2).
 *
 * `classifyIntegrity` fetches npm's current published `dist.integrity` for every
 * locked npm server with a baseline and sorts every locked registry server into
 * buckets. `frozenVerdict` turns that classification into a structured pass/block
 * decision. Both are CLIENT-FREE and pure of output, so:
 *   - `up --frozen` (the pre-install gate) consumes them and renders install-flavored
 *     block text, and
 *   - `mcpm verify` (D2 — the repo-only CI gate) consumes them on a hosted runner
 *     where zero AI clients are installed, rendering verify-flavored text / `--json`.
 *
 * HONESTY BOUNDARY: a block means npm's PUBLISHED RECORD diverged from (or can't be
 * matched against) your lock — NOT that mcpm caught malicious bytes. npx/uvx fetch the
 * artifact independently at server launch, so this is a deterministic tripwire on the
 * registry's published metadata, not code interception.
 */

import type { LockFile, NpmIntegritySnapshot } from "./schema.js";
import { isLockedRegistryServer } from "./schema.js";
import { compareIntegrity } from "../registry/npm-integrity.js";

/** The npm-integrity fetcher (injected so tests and the CLI share one signature). */
export type FetchNpmIntegrity = (
  identifier: string,
  npmVersion: string
) => Promise<NpmIntegritySnapshot | undefined>;

/** A locked registry server entry (npm or other), as stored in mcpm-lock.yaml. */
type LockedRegistryEntry = {
  version: string;
  registryType: string;
  identifier: string;
  trust: unknown;
  npmIntegrity?: { npmVersion: string; integrity: string };
};

/** Server coordinate carried through integrity classification. */
export type IntegrityCoord = { name: string; identifier: string; npmVersion: string };

export interface IntegrityClassification {
  /** locked dist.integrity differs from npm's current published record. */
  readonly drift: (IntegrityCoord & { oldIntegrity: string; newIntegrity: string })[];
  /** npm's record uses no algorithm in common with the lock — cannot compare. */
  readonly formatOnly: IntegrityCoord[];
  /** fetch returned nothing (offline / 404 / no comparable dist.integrity). */
  readonly couldNotVerify: IntegrityCoord[];
  /** npm servers whose lock entry has no npmIntegrity baseline at all. */
  readonly absentBaseline: string[];
  /** servers integrity-verification cannot check at all: non-npm registry servers
   *  (pypi/oci — no baseline mechanism yet) plus url servers (no package coordinate). */
  readonly unenforceable: string[];
  /** count of npm servers that DID have a baseline (to tell lock-wide vs mixed gaps). */
  readonly checkedNpmCount: number;
}

/**
 * Fetches npm's current published dist.integrity for every locked npm server with a
 * baseline (one batched Promise.all) and sorts every locked registry server into
 * buckets. Pure of output.
 */
export async function classifyIntegrity(
  lockFile: LockFile,
  fetchNpmIntegrity: FetchNpmIntegrity
): Promise<IntegrityClassification> {
  const registryEntries = Object.entries(lockFile.servers).filter(([, locked]) =>
    isLockedRegistryServer(locked)
  ) as [string, LockedRegistryEntry][];

  const npmEntries = registryEntries.filter(([, l]) => l.registryType === "npm");
  // Everything that is NOT an npm registry server can't be integrity-checked:
  // pypi/oci (no baseline mechanism yet) and url servers (no package coordinate).
  const npmNames = new Set(npmEntries.map(([name]) => name));
  const unenforceable = Object.keys(lockFile.servers).filter((name) => !npmNames.has(name));

  const checkable = npmEntries.filter(([, l]) => l.npmIntegrity !== undefined);
  const absentBaseline = npmEntries
    .filter(([, l]) => l.npmIntegrity === undefined)
    .map(([name]) => name);

  const fresh = await Promise.all(
    checkable.map(([, l]) => fetchNpmIntegrity(l.identifier, l.npmIntegrity!.npmVersion))
  );

  const drift: IntegrityClassification["drift"] = [];
  const formatOnly: IntegrityCoord[] = [];
  const couldNotVerify: IntegrityCoord[] = [];

  for (let i = 0; i < checkable.length; i++) {
    const [name, locked] = checkable[i]!;
    const baseline = locked.npmIntegrity!;
    const snap = fresh[i];
    const coord: IntegrityCoord = { name, identifier: locked.identifier, npmVersion: baseline.npmVersion };

    if (snap === undefined) {
      couldNotVerify.push(coord);
      continue;
    }
    const cmp = compareIntegrity(baseline.integrity, snap.integrity);
    if (cmp === "equal") continue;
    if (cmp === "differ") {
      drift.push({ ...coord, oldIntegrity: baseline.integrity, newIntegrity: snap.integrity });
    } else {
      formatOnly.push(coord);
    }
  }

  return { drift, formatOnly, couldNotVerify, absentBaseline, unenforceable, checkedNpmCount: checkable.length };
}

// ---------------------------------------------------------------------------
// Verdict — the shared pass/block decision (rendered by each command's own text)
// ---------------------------------------------------------------------------

export type FrozenBlock =
  | { name: string; reason: "drift"; identifier: string; npmVersion: string; oldIntegrity: string; newIntegrity: string }
  | { name: string; reason: "format"; identifier: string; npmVersion: string }
  | { name: string; reason: "could-not-verify"; identifier: string; npmVersion: string }
  | { name: string; reason: "missing-baseline" };

export interface FrozenVerdict {
  /** true iff nothing blocks and it is not the benign no-baselines refuse case. */
  readonly ok: boolean;
  /** benign refuse-to-run: the whole lock predates baselines / was locked offline. */
  readonly noBaselines: boolean;
  /** blocking servers, in stable order (drift → format → could-not-verify → missing-baseline). */
  readonly blocks: FrozenBlock[];
  /** pypi/oci/url servers with no baseline mechanism — a coverage notice, never a block. */
  readonly unenforceable: string[];
  /** npm servers that had a baseline to check against. */
  readonly checkedNpmCount: number;
}

/**
 * The pass/block decision. A lock where NO npm server has a baseline is benign
 * (`noBaselines`) — a refuse-to-run with instructions, NOT a per-server verdict.
 * When some servers DO have baselines, a missing one is a suspicious mixed gap → block.
 */
export function frozenVerdict(c: IntegrityClassification): FrozenVerdict {
  const noBaselines = c.absentBaseline.length > 0 && c.checkedNpmCount === 0;

  const blocks: FrozenBlock[] = [];
  for (const d of c.drift) {
    blocks.push({
      name: d.name,
      reason: "drift",
      identifier: d.identifier,
      npmVersion: d.npmVersion,
      oldIntegrity: d.oldIntegrity,
      newIntegrity: d.newIntegrity,
    });
  }
  for (const f of c.formatOnly) {
    blocks.push({ name: f.name, reason: "format", identifier: f.identifier, npmVersion: f.npmVersion });
  }
  for (const v of c.couldNotVerify) {
    blocks.push({ name: v.name, reason: "could-not-verify", identifier: v.identifier, npmVersion: v.npmVersion });
  }
  // Mixed gap only — the lock-wide-no-baseline case is `noBaselines`, handled above.
  if (!noBaselines) {
    for (const name of c.absentBaseline) {
      blocks.push({ name, reason: "missing-baseline" });
    }
  }

  return {
    ok: !noBaselines && blocks.length === 0,
    noBaselines,
    blocks,
    unenforceable: c.unenforceable,
    checkedNpmCount: c.checkedNpmCount,
  };
}
