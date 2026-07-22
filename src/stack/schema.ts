/**
 * Stack file schemas — Zod definitions for mcpm.yaml and mcpm-lock.yaml.
 *
 * Single source of truth: all TypeScript types are inferred via z.infer<>.
 * Includes YAML parse/serialize helpers.
 */

import { z } from "zod";
import { readFile } from "fs/promises";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { isEnoent } from "../utils/fs.js";

// ---------------------------------------------------------------------------
// mcpm.yaml — Stack file schema
// ---------------------------------------------------------------------------

/** Environment variable declaration in a stack file. */
const StackEnvVarSchema = z.object({
  required: z.boolean().optional().default(false),
  secret: z.boolean().optional().default(false),
  default: z.string().optional(),
});

/** A server entry that resolves from the MCP registry by version. */
const RegistryServerSchema = z
  .object({
    version: z.string(),
    profiles: z.array(z.string()).optional(),
    env: z.record(z.string(), StackEnvVarSchema).optional(),
  })
  .strict();

/** A server entry that connects via direct URL (HTTP remote). */
const UrlServerSchema = z
  .object({
    url: z.string().url(),
    profiles: z.array(z.string()).optional(),
    env: z.record(z.string(), StackEnvVarSchema).optional(),
  })
  .strict();

/**
 * Server entry union: first-match semantics via z.union.
 * `.strict()` on each variant ensures mutual exclusion — an object with
 * both `version` and `url` fields will fail both schemas.
 */
const StackServerSchema = z.union([RegistryServerSchema, UrlServerSchema]);

/** Trust policy block — gates `mcpm up` based on security posture. */
const PolicySchema = z.object({
  minTrustScore: z.number().int().min(0).max(100).optional(),
  blockOnScoreDrop: z.boolean().optional().default(false),
  minReleaseAgeHours: z.number().int().min(0).optional(),
  // Bare .optional() (NOT .default(false)): a default would make the inferred
  // Policy output type require the field in every hand-built literal.
  // Consumers check `=== true` (undefined ≡ false).
  blockInstallScripts: z.boolean().optional(),
  // H9 (fail-closed): durable consent to install URL/HTTP-transport servers
  // that run UNGUARDED (no relay can wrap a non-stdio transport). When true, a
  // url: server is permitted without the per-invocation `--allow-unguarded`
  // flag. This is the ONE place a policy bit grants an explicit DOWNGRADE the
  // user wrote into their own stack file (principle 1 only forbids
  // server-declared metadata lowering scrutiny; this is user intent). The
  // MCP-surface kill-switch `UpOptions.allowUrlServers === false` still wins —
  // an untrusted caller can never opt in. Bare .optional(): consumers check
  // `=== true`.
  allowUrlServers: z.boolean().optional(),
  // F2 (warn-tier, opt-in): cross-server tool-name-collision check at `mcpm up`.
  // When true, `up` compares the guarded tool inventories (read from pins) across
  // the resolved server set and reports any tool name exposed by >= 2 servers — a
  // shadowing signal. Best-effort over ALREADY-GUARDED servers only (a server with
  // no pin baseline contributes no names); not a fresh-install control. Findings
  // are advisory (informational) on an interactive run; under `--ci` a collision
  // exits non-zero. Bare .optional(): consumers check `=== true`.
  checkShadowing: z.boolean().optional(),
  // F3 (fail-closed): arm the `up --frozen` integrity freeze from the stack file —
  // `up` verifies every locked npm server's published dist.integrity BEFORE
  // installing and BLOCKS the whole run (installs nothing, exits nonzero) on drift /
  // unverifiable / a suspicious missing baseline. Bare .optional(): consumers check
  // `=== true`. Honest scope: npm-only; non-npm (pypi/oci) get a coverage notice.
  frozen: z.boolean().optional(),
});

/** Top-level mcpm.yaml schema. */
export const StackFileSchema = z.object({
  version: z.string().refine((v) => v === "1", {
    message: 'Unsupported stack file version. Expected "1".',
  }),
  policy: PolicySchema.optional(),
  servers: z.record(z.string(), StackServerSchema),
});

// ---------------------------------------------------------------------------
// mcpm-lock.yaml — Lock file schema
// ---------------------------------------------------------------------------

/**
 * Npm artifact integrity snapshot captured at lock time (H11 slice 1).
 *
 * Records the npm registry's published `dist.integrity` (SRI) for the exact
 * npm package coordinate so `mcpm up` can re-check whether the published record
 * changed (supply-chain drift detection). This checks the *registry's published
 * record*, NOT the bytes the agent runs (npx/uvx handle artifact execution).
 */
const NpmIntegritySnapshotSchema = z.object({
  /** The npm package version coordinate used to fetch the integrity (e.g. "1.3.0"). */
  npmVersion: z.string(),
  /** SRI string from npm's dist.integrity (e.g. "sha512-...=="). */
  integrity: z.string(),
});

export type NpmIntegritySnapshot = z.infer<typeof NpmIntegritySnapshotSchema>;

/**
 * Parsed build-identity tuple from an npm Sigstore attestation (F8 slice 1).
 * Extracted by parsing only — NOT cryptographically verified. Every field is
 * optional because attestation shapes vary (SLSA v1 vs v0.2) and legacy bundles
 * lack the numeric ids. The numeric repository/owner ids are the drift anchors
 * (immutable across repo renames).
 */
const ProvenanceIdentitySchema = z.object({
  sourceRepo: z.string().max(2048).optional(),
  repositoryId: z.string().max(64).optional(),
  repositoryOwnerId: z.string().max(64).optional(),
  workflowPath: z.string().max(2048).optional(),
  workflowRef: z.string().max(2048).optional(),
  builderId: z.string().max(2048).optional(),
  commitSha: z.string().max(128).optional(),
  predicateType: z.string().max(256).optional(),
  /** subject digest — a free cross-bind to dist.integrity's tarball record. */
  subjectDigestSha512: z.string().max(256).optional(),
});

export type ProvenanceIdentity = z.infer<typeof ProvenanceIdentitySchema>;

/**
 * npm provenance snapshot (F8 slice 1 — parse-only, WARN-only). `mode` is a
 * literal reserving the shape for a future crypto slice (which alone may report
 * a "verified" mode). `identity` is present only when `status: "attested"`.
 */
/**
 * Cryptographic-verification outcome (F8 crypto slice). ADDITIVE and bare-optional
 * on the snapshot: `status`/`mode` stay byte-identical so v0.22.0 lockfiles (whose
 * parseLockFile safeParse-throws on an unknown enum/literal) keep parsing. Crypto
 * NEVER downgrades `status` — a crypto miss leaves "attested" as "attested".
 */
const NpmProvenanceVerificationSchema = z.object({
  outcome: z.enum(["verified", "could-not-verify"]),
  /** Short machine reason on could-not-verify (a @sigstore error code or our gate). */
  reason: z.string().max(300).optional(),
  /** Verified signer workflow identity (SAN) — recorded, not gated on equality. */
  signerSan: z.string().max(2048).optional(),
  /** Verified signer OIDC issuer. */
  signerIssuer: z.string().max(2048).optional(),
});

export type NpmProvenanceVerification = z.infer<typeof NpmProvenanceVerificationSchema>;

export const NpmProvenanceSnapshotSchema = z.object({
  npmVersion: z.string(),
  status: z.enum(["attested", "unsigned", "unsupported"]),
  mode: z.literal("registry-record"),
  identity: ProvenanceIdentitySchema.optional(),
  verification: NpmProvenanceVerificationSchema.optional(),
  /**
   * On a crypto-`verified` snapshot, `identity` is the UNFORGEABLE SAN-derived tuple —
   * but that lives in a different namespace than a parse-only snapshot's payload tuple
   * (the SAN names the CALLED reusable workflow's repo; the payload names the CALLER's).
   * To drift-compare a verified snapshot against a parse-only one WITHOUT false-positiving
   * on reusable workflows, we also retain the original parse-only payload tuple here.
   * Present only on `verified` snapshots (bare-optional: absent on all others + old locks).
   */
  payloadIdentity: ProvenanceIdentitySchema.optional(),
});

export type NpmProvenanceSnapshot = z.infer<typeof NpmProvenanceSnapshotSchema>;

/** Trust snapshot as recorded at lock time. */
const TrustSnapshotSchema = z.object({
  score: z.number(),
  maxPossible: z.number(),
  level: z.enum(["safe", "caution", "risky"]),
  assessedAt: z.string(),
});

/** A locked registry server entry. */
const LockedRegistryServerSchema = z.object({
  version: z.string(),
  registryType: z.string(),
  identifier: z.string(),
  trust: TrustSnapshotSchema,
  /**
   * Npm artifact integrity snapshot (H11 slice 1). Optional: absent on old
   * lockfiles (backward-compatible) and when the npm coordinate was not a
   * concrete exact version at lock time. Old lockfiles parse fine because the
   * schema is non-strict and this field is bare .optional().
   */
  npmIntegrity: NpmIntegritySnapshotSchema.optional(),
  /**
   * npm provenance snapshot (F8 slice 1). Optional/bare like npmIntegrity: absent
   * on old lockfiles and non-npm coordinates. Parse-only, never blocks.
   */
  provenance: NpmProvenanceSnapshotSchema.optional(),
});

/** A locked URL server entry (no version resolution). */
const LockedUrlServerSchema = z.object({
  url: z.string(),
  trust: TrustSnapshotSchema.optional(),
});

const LockedServerSchema = z.union([
  LockedRegistryServerSchema,
  LockedUrlServerSchema,
]);

/** Top-level mcpm-lock.yaml schema. */
export const LockFileSchema = z.object({
  lockfileVersion: z.literal(1),
  lockedAt: z.string(),
  servers: z.record(z.string(), LockedServerSchema),
});

// ---------------------------------------------------------------------------
// Inferred types
// ---------------------------------------------------------------------------

export type StackFile = z.infer<typeof StackFileSchema>;
export type StackServer = z.infer<typeof StackServerSchema>;
export type StackEnvVar = z.infer<typeof StackEnvVarSchema>;
export type Policy = z.infer<typeof PolicySchema>;
export type LockFile = z.infer<typeof LockFileSchema>;
export type LockedServer = z.infer<typeof LockedServerSchema>;
export type TrustSnapshot = z.infer<typeof TrustSnapshotSchema>;

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

/** Returns true if the server entry has a `version` field (registry-resolved). */
export function isRegistryServer(
  server: StackServer
): server is z.infer<typeof RegistryServerSchema> {
  return "version" in server;
}

/** Returns true if the server entry has a `url` field (direct HTTP remote). */
export function isUrlServer(
  server: StackServer
): server is z.infer<typeof UrlServerSchema> {
  return "url" in server;
}

/** Returns true if the locked entry has a `version` field. */
export function isLockedRegistryServer(
  server: LockedServer
): server is z.infer<typeof LockedRegistryServerSchema> {
  return "version" in server;
}

// ---------------------------------------------------------------------------
// Parse / serialize helpers
// ---------------------------------------------------------------------------

/**
 * Read and validate an mcpm.yaml stack file.
 * Throws with a descriptive Zod error if validation fails.
 */
export async function parseStackFile(filePath: string): Promise<StackFile> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) {
      throw new Error(`Stack file not found: ${filePath}`);
    }
    throw err;
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch {
    throw new Error(`Invalid YAML in stack file: ${filePath}`);
  }

  const result = StackFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid stack file (${filePath}):\n${issues}`);
  }

  return result.data;
}

/**
 * Read and validate an mcpm-lock.yaml lock file.
 * Returns null if the file does not exist (not an error — lock is optional).
 */
export async function parseLockFile(
  filePath: string
): Promise<LockFile | null> {
  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) {
      return null;
    }
    throw err;
  }

  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch {
    throw new Error(`Invalid YAML in lock file: ${filePath}`);
  }

  const result = LockFileSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join(".")}: ${i.message}`)
      .join("\n");
    throw new Error(`Invalid lock file (${filePath}):\n${issues}`);
  }

  return result.data;
}

/**
 * Serialize a stack or lock file to YAML string.
 */
export function serializeYaml(data: StackFile | LockFile): string {
  return stringifyYaml(data, { lineWidth: 0 });
}
