/**
 * .mcpm-publish.yaml manifest schema and reader.
 */

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { isEnoent } from "../../utils/fs.js";

/**
 * The registry's server.schema.json URI, pinned to the same dated schema
 * version the description-cap check above already targets (2025-12-11).
 */
export const SERVER_SCHEMA_URL =
  "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";

// The official MCP Registry's server.schema.json sets maxLength: 100 on
// `description` (confirmed against static.modelcontextprotocol.io); mcpm's
// own manifest schema previously only checked min(1), so an over-cap
// description scaffolded fine, passed `mcpm publish check`, and was only
// rejected by the registry at submit time (backlog #85).
const DESCRIPTION_MAX = 100;

// `maxLength` counts CODE POINTS, not UTF-16 units: server.schema.json is JSON
// Schema draft-07, whose maxLength is "the number of characters as defined by
// RFC 8259" (code points), and the registry enforces it with
// santhosh-tekuri/jsonschema v5, which measures with `utf8.RuneCount`. Zod's
// own `.max()` already counts code points, so `.length` here only made the
// message contradict the check it explains — one emoji is two UTF-16 units, so
// a description exactly ONE character over the cap reported "yours is 202".
const descriptionLength = (value: string): number => [...value].length;

const descriptionCapMessage = (value: string): string =>
  `the MCP registry caps description at ${DESCRIPTION_MAX} characters (server.schema.json maxLength); yours is ${descriptionLength(value)}`;

/**
 * The scaffold wizard's description check, shared with the schema below so the
 * prompt cannot refuse what the manifest — and the registry — would accept.
 * `@inquirer/prompts` accepts on `true` and re-prompts with the returned string.
 * publish-scaffold.test.ts pins that the wizard passes THIS function, because a
 * re-inlined `value.length` check would silently refuse a registry-legal
 * description again (one emoji is two UTF-16 units but one character).
 */
export const validateDescription = (value: string): true | string =>
  descriptionLength(value) <= DESCRIPTION_MAX ? true : descriptionCapMessage(value);

// Registry-shaped sub-schemas, matching ServerJSON's Package/Transport/
// KeyValueInput/Repository shapes 1:1 (confirmed against the live
// registry.modelcontextprotocol.io/openapi.yaml, 2026-09-14) so
// `manifestToServerJson` can pass them through with no remapping.
const TransportSchema = z.object({
  type: z.enum(["stdio", "streamable-http", "sse"]),
  url: z.string().url().optional(),
});

const EnvVarSchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  isRequired: z.boolean().optional(),
  isSecret: z.boolean().optional(),
  default: z.string().optional(),
});

// The registry's Repository schema has no `type` field (`additionalProperties:
// false` rejects one) — the hosting service goes in `source` (e.g. "github"),
// confirmed live: `{type:"git",...}` 422s with "unexpected property", while
// `{source:"github",...}` validates.
const RepositorySchema = z.object({
  source: z.string().min(1),
  url: z.string().url(),
});

export const PublishManifestSchema = z.object({
  name: z.string().min(1),
  description: z.string().min(1).max(DESCRIPTION_MAX, {
    error: (issue) => descriptionCapMessage(String(issue.input)),
  }),
  homepage: z.string().url().optional(),
  tags: z.array(z.string()).default([]),
  package: z.object({
    registryType: z.enum(["npm", "pypi", "oci"]),
    identifier: z.string().min(1),
  }),
  /** Falls back to package.json's version in cwd when omitted — see resolveVersion. */
  version: z.string().min(1).optional(),
  transport: TransportSchema.default({ type: "stdio" }),
  runtimeHint: z.string().min(1).optional(),
  /**
   * Shorthand: a plain string list (e.g. ["serve"]), each mapped to a
   * registry `{type:"positional", value}` Argument by manifestToServerJson.
   */
  runtimeArguments: z.array(z.string()).optional(),
  environmentVariables: z.array(EnvVarSchema).optional(),
  repository: RepositorySchema.optional(),
  websiteUrl: z.string().url().optional(),
});

export type PublishManifest = z.infer<typeof PublishManifestSchema>;

// ---------------------------------------------------------------------------
// ServerJSON — the exact body POSTed to /v0.1/publish (and /v0.1/validate).
// ---------------------------------------------------------------------------

export interface ServerJsonArgument {
  type: "positional" | "named";
  value: string;
}

export interface ServerJsonPackage {
  registryType: "npm" | "pypi" | "oci";
  identifier: string;
  version: string;
  transport: { type: string; url?: string };
  runtimeHint?: string;
  runtimeArguments?: ServerJsonArgument[];
  environmentVariables?: z.infer<typeof EnvVarSchema>[];
}

export interface ServerJson {
  $schema: string;
  name: string;
  description: string;
  version: string;
  websiteUrl?: string;
  repository?: { source: string; url: string };
  packages: ServerJsonPackage[];
}

/**
 * Builds exactly the registry's ServerJSON shape for POST /v0.1/publish (and
 * /v0.1/validate) — verified live against registry.modelcontextprotocol.io.
 */
export function manifestToServerJson(manifest: PublishManifest, version: string): ServerJson {
  const websiteUrl = manifest.websiteUrl ?? manifest.homepage;
  return {
    $schema: SERVER_SCHEMA_URL,
    name: manifest.name,
    description: manifest.description,
    version,
    ...(websiteUrl ? { websiteUrl } : {}),
    ...(manifest.repository ? { repository: manifest.repository } : {}),
    packages: [
      {
        registryType: manifest.package.registryType,
        identifier: manifest.package.identifier,
        version,
        transport: manifest.transport,
        ...(manifest.runtimeHint ? { runtimeHint: manifest.runtimeHint } : {}),
        ...(manifest.runtimeArguments?.length
          ? {
              runtimeArguments: manifest.runtimeArguments.map(
                (value): ServerJsonArgument => ({ type: "positional", value })
              ),
            }
          : {}),
        ...(manifest.environmentVariables?.length
          ? { environmentVariables: manifest.environmentVariables }
          : {}),
      },
    ],
  };
}

/**
 * Resolves the version to publish: the manifest's own `version` field, else
 * package.json's `version` in cwd, else a clear error. mcpm's own manifest
 * omits `version` deliberately — the release workflow's `npm pkg set
 * version=<tag>` already makes package.json the source of truth.
 */
export async function resolveVersion(manifest: PublishManifest, cwd = process.cwd()): Promise<string> {
  if (manifest.version) return manifest.version;

  const pkgPath = resolve(cwd, "package.json");
  let raw: string;
  try {
    raw = await readFile(pkgPath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) {
      throw new Error(
        [
          "mcpm publish: No version found.",
          "  Cause: .mcpm-publish.yaml has no `version` and no package.json exists in this directory.",
          "  Fix:   Add `version: x.y.z` to .mcpm-publish.yaml, or run from a directory with a package.json.",
        ].join("\n")
      );
    }
    throw err;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`mcpm publish: Invalid package.json: ${err instanceof Error ? err.message : String(err)}`);
  }
  const version = (parsed as { version?: unknown }).version;
  if (typeof version !== "string" || version.length === 0) {
    throw new Error(
      [
        "mcpm publish: No version found.",
        "  Cause: .mcpm-publish.yaml has no `version` and package.json has no `version` field.",
        "  Fix:   Add `version: x.y.z` to .mcpm-publish.yaml, or a `version` field to package.json.",
      ].join("\n")
    );
  }
  return version;
}

const MANIFEST_FILENAME = ".mcpm-publish.yaml";

/**
 * Reads and validates .mcpm-publish.yaml from cwd.
 * Returns null if the file does not exist.
 */
export async function readManifest(cwd = process.cwd()): Promise<PublishManifest | null> {
  const manifestPath = resolve(cwd, MANIFEST_FILENAME);
  let raw: string;
  try {
    raw = await readFile(manifestPath, "utf-8");
  } catch (err) {
    if (isEnoent(err)) return null;
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = parseYaml(raw);
  } catch (err) {
    throw new Error(`Invalid .mcpm-publish.yaml: ${err instanceof Error ? err.message : String(err)}`);
  }

  // safeParse + formatted issues (not .parse()'s raw ZodError dump) so the
  // user sees a readable "path: message" list, matching parseStackFile's
  // and parseLockFile's pattern in src/stack/schema.ts.
  const result = PublishManifestSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues.map((i) => `  ${i.path.join(".")}: ${i.message}`).join("\n");
    throw new Error(`Invalid .mcpm-publish.yaml:\n${issues}`);
  }
  return result.data;
}
