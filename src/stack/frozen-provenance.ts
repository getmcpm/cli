/**
 * Shared lockfile PROVENANCE verification (F8 verify-time / "B3").
 *
 * The crypto sibling of frozen-verify.ts. Where the integrity gate compares npm's
 * currently-published dist.integrity to the locked baseline, this RE-RUNS the
 * offline Sigstore crypto verification for every npm server the lock recorded as
 * cryptographically `verified`, and BLOCKS when that attestation regresses for the
 * SAME pinned coordinate:
 *   - signer-changed — still verifies, but under a DIFFERENT unforgeable Fulcio
 *                      SAN/issuer than the lock recorded (an attestation swap);
 *   - regression     — was verified; now crypto FAILS, or the attestation is GONE
 *                      (a signed→unsigned rug-pull on a pinned coordinate);
 *   - unverifiable   — couldn't re-verify this run (offline / endpoint error /
 *                      shape no longer a recognizable SLSA record) → re-run.
 *
 * EVIDENCE-GATED (the zero-FP anchor): only servers with a locked
 * `verification.outcome === "verified"` baseline are checked. A lock with none —
 * every pre-crypto lock, and every lock of the (overwhelmingly unsigned) MCP
 * ecosystem — yields an empty verdict and changes nothing. Unsigned/attested-only
 * servers are NEVER provenance-blocked.
 *
 * Why signer-SAN EQUALITY is safe to HARD-gate here, while compareProvenance's
 * payload-identity drift is WARN-only: the SAN is the UNFORGEABLE Fulcio cert
 * identity, and an npm version is IMMUTABLE — the published attestation for a
 * pinned coordinate is fixed forever. An org transfer changes the SAN only for
 * FUTURE publishes; the locked version keeps its original signer. So a SAN change
 * on a pinned coordinate is an attestation SWAP, not a legitimate rename.
 * (compareProvenance gates the FORGEABLE payload tuple ACROSS versions, where a
 * transfer is a genuine false positive → WARN.)
 *
 * SCOPE of the signer equality (be honest about it): for a `verified` fresh result
 * the gate compares only the SAN + issuer the lock recorded. Two soundness
 * assumptions: (1) the issuer is pinned to GitHub-Actions OIDC by the crypto layer,
 * so the SAN is the discriminating field; (2) the SAN uniquely identifies the
 * publisher. Assumption (2) is weaker for a package published via a SHARED REUSABLE
 * WORKFLOW — the Fulcio SAN is the job_workflow_ref of the CALLED workflow, which a
 * different caller repo can also legitimately use. A verified baseline with no
 * recorded SAN cannot be equality-checked at all → treated as `unverifiable`
 * (fail-closed, re-lock), never a vacuous pass.
 *
 * HONESTY BOUNDARY (inherited): a block means npm's PUBLISHED attestation record
 * for a pinned coordinate diverged from what cryptographically verified at lock
 * time — NOT that mcpm caught malicious bytes. Pure of output; consumed by both
 * `mcpm verify` and `up --frozen`.
 */

import type { LockFile, NpmProvenanceSnapshot } from "./schema.js";
import { isLockedRegistryServer } from "./schema.js";
import type { FetchNpmIntegrity } from "./frozen-verify.js";

/** The provenance fetcher (injected; the fetchNpmProvenance crypto-path subset). */
export type FetchNpmProvenance = (
  identifier: string,
  npmVersion: string,
  opts: { integritySri: string }
) => Promise<NpmProvenanceSnapshot | undefined>;

export type ProvenanceBlockReason = "signer-changed" | "regression" | "unverifiable";

export interface ProvenanceBlock {
  readonly name: string;
  readonly identifier: string;
  readonly npmVersion: string;
  readonly reason: ProvenanceBlockReason;
  /** Human sub-cause (the fresh could-not-verify code, the signer delta, etc.). */
  readonly detail: string;
}

export interface ProvenanceVerdict {
  /** true iff no verified-baseline server regressed. */
  readonly ok: boolean;
  /** blocking servers, in stable input order. */
  readonly blocks: ProvenanceBlock[];
  /** npm servers that carried a crypto-`verified` baseline (the checked set). */
  readonly checkedVerifiedCount: number;
}

/** A locked npm entry, as stored in mcpm-lock.yaml (subset this module reads). */
type LockedNpmEntry = {
  registryType: string;
  identifier: string;
  provenance?: NpmProvenanceSnapshot;
};

/** The crypto-`verified` baseline for one server, or undefined if not evidence-gated in. */
type VerifiedBaseline = {
  npmVersion: string;
  signerSan: string | undefined;
  signerIssuer: string | undefined;
};

function verifiedBaseline(locked: LockedNpmEntry): VerifiedBaseline | undefined {
  const prov = locked.provenance;
  // Only an ATTESTED snapshot that CRYPTOGRAPHICALLY verified at lock time is gated.
  if (prov?.status !== "attested" || prov.verification?.outcome !== "verified") {
    return undefined;
  }
  return {
    npmVersion: prov.npmVersion,
    signerSan: prov.verification.signerSan,
    signerIssuer: prov.verification.signerIssuer,
  };
}

/**
 * Re-verify provenance for every crypto-`verified` npm server and classify any
 * regression. Fetches CURRENT integrity per checked server (to bind the crypto
 * re-verify's subject to the tarball npm serves now), then re-fetches+re-verifies
 * the attestation. Pure of output; NEVER throws (the injected fetchers fail-open
 * to undefined, which classifies as `unverifiable`).
 *
 * ponytail: re-fetches integrity for the (tiny) verified subset rather than
 * threading classifyIntegrity's fetch — two GETs in a CI gate is nothing, and it
 * keeps the two classifiers independent. Share the fetch if a lock ever carries
 * dozens of verified servers (it won't).
 */
export async function classifyProvenance(
  lockFile: LockFile,
  fetchNpmIntegrity: FetchNpmIntegrity,
  fetchNpmProvenance: FetchNpmProvenance
): Promise<ProvenanceVerdict> {
  const checked = (
    Object.entries(lockFile.servers).filter(([, l]) =>
      isLockedRegistryServer(l)
    ) as [string, LockedNpmEntry][]
  )
    .filter(([, l]) => l.registryType === "npm")
    .map(([name, l]) => ({ name, locked: l, baseline: verifiedBaseline(l) }))
    .filter(
      (e): e is { name: string; locked: LockedNpmEntry; baseline: VerifiedBaseline } =>
        e.baseline !== undefined
    );

  const blocks = (
    await Promise.all(
      checked.map(async ({ name, locked, baseline }) => {
        const coord = { name, identifier: locked.identifier, npmVersion: baseline.npmVersion };
        try {
          // The crypto verify binds the attestation's subject to the tarball npm
          // serves NOW, so we need the CURRENT integrity — not the locked baseline
          // (verifying against a stale SRI would miss a re-published tarball).
          const integ = await fetchNpmIntegrity(locked.identifier, baseline.npmVersion);
          if (integ === undefined) {
            return {
              ...coord,
              reason: "unverifiable" as const,
              detail: "could not fetch npm's published integrity to bind the attestation",
            };
          }
          const fresh = await fetchNpmProvenance(locked.identifier, baseline.npmVersion, {
            integritySri: integ.integrity,
          });
          return classifyOne(coord, baseline, fresh);
        } catch {
          // An injected fetcher that throws (rather than failing open to undefined)
          // must NOT abort the whole gate or fail OPEN — fail closed for this server.
          return {
            ...coord,
            reason: "unverifiable" as const,
            detail: "re-verification errored this run (fetcher threw)",
          };
        }
      })
    )
  ).filter((b): b is ProvenanceBlock => b !== undefined);

  return { ok: blocks.length === 0, blocks, checkedVerifiedCount: checked.length };
}

type Coord = { name: string; identifier: string; npmVersion: string };

/** Classify one verified-baseline server's fresh re-verification, or undefined = PASS. */
function classifyOne(
  coord: Coord,
  baseline: VerifiedBaseline,
  fresh: NpmProvenanceSnapshot | undefined
): ProvenanceBlock | undefined {
  // Fail-open fetch (offline / endpoint error) → can't re-check → re-run.
  if (fresh === undefined) {
    return { ...coord, reason: "unverifiable", detail: "no fresh attestation record this run (offline or endpoint error)" };
  }
  // The attestation that verified at lock time is GONE for this pinned coordinate.
  if (fresh.status === "unsigned") {
    return { ...coord, reason: "regression", detail: "the attestation that verified at lock time is no longer published (now unsigned)" };
  }
  // 200 but no longer a recognizable/comparable SLSA record → can't re-verify.
  if (fresh.status !== "attested") {
    return { ...coord, reason: "unverifiable", detail: "attestation shape is no longer a recognizable SLSA record" };
  }
  const v = fresh.verification;
  // Attested but crypto didn't run this fetch (non-SLSA-v1 shape, or crypto module
  // unavailable) — we cannot re-assert the cryptographic guarantee → re-run.
  if (v === undefined) {
    return { ...coord, reason: "unverifiable", detail: "attestation present but cryptographic verification did not run this fetch" };
  }
  // Present bundle that no longer cryptographically verifies → hard regression.
  if (v.outcome === "could-not-verify") {
    return { ...coord, reason: "regression", detail: `attestation no longer cryptographically verifies (${v.reason ?? "crypto failure"})` };
  }
  // outcome === "verified": the unforgeable signer identity must match the lock.
  // A verified baseline with NO recorded SAN cannot be equality-checked — comparing
  // undefined === undefined would VACUOUSLY pass, letting any SAN-less verifying
  // attestation through. Fail closed instead (re-lock records the SAN).
  if (baseline.signerSan === undefined) {
    return { ...coord, reason: "unverifiable", detail: "verified baseline lacks a recorded signer SAN — cannot assert signer equality; re-lock to record it" };
  }
  if (v.signerSan !== baseline.signerSan || v.signerIssuer !== baseline.signerIssuer) {
    // Report whichever field actually changed — a bare SAN delta would print "X → X"
    // when only the issuer differs.
    const deltas: string[] = [];
    if (v.signerSan !== baseline.signerSan) {
      deltas.push(`SAN ${baseline.signerSan ?? "(none)"} → ${v.signerSan ?? "(none)"}`);
    }
    if (v.signerIssuer !== baseline.signerIssuer) {
      deltas.push(`issuer ${baseline.signerIssuer ?? "(none)"} → ${v.signerIssuer ?? "(none)"}`);
    }
    return { ...coord, reason: "signer-changed", detail: `signer identity changed: ${deltas.join("; ")}` };
  }
  return undefined; // still verified, same signer → PASS
}
