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
