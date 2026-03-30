/**
 * Zod schemas — single source of truth for all registry API types.
 *
 * All TypeScript types are derived from these via z.infer<>.
 * Validated against the official MCP Registry API v0.1 response shape.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Sub-schemas
// ---------------------------------------------------------------------------

export const RepositorySchema = z.object({
  url: z.string().optional(),
  source: z.string().optional(),
  id: z.union([z.string(), z.number()]).optional(),
  subfolder: z.string().optional(),
});

export const IconSchema = z.object({
  src: z.string(),
  mimeType: z.string().optional(),
});

export const EnvVarSchema = z.object({
  name: z.string(),
  description: z.string().optional(),
  isRequired: z.boolean().optional(),
  isSecret: z.boolean().optional(),
  default: z.string().optional(),
});

export const TransportSchema = z.object({
  type: z.string(),
});

/**
 * Package entry — discriminated union on registryType.
 * We use z.string() for registryType so unknown future types pass through
 * rather than hard-failing, while still retaining the typed field.
 */
export const PackageSchema = z.object({
  registryType: z.string(),
  identifier: z.string(),
  version: z.string().optional(),
  transport: TransportSchema.optional(),
  environmentVariables: z.array(EnvVarSchema).default([]),
  runtimeArguments: z.array(
    z.union([
      z.string(),
      z.object({ type: z.string(), value: z.string() }).passthrough(),
    ])
  ).optional(),
});

export const RemoteHeaderSchema = z.object({
  name: z.string(),
  isRequired: z.boolean().optional(),
  isSecret: z.boolean().optional(),
  description: z.string().optional(),
});

export const RemoteSchema = z.object({
  type: z.string(),
  url: z.string().url(),
  headers: z.array(RemoteHeaderSchema).default([]),
});

export const OfficialMetaSchema = z.object({
  status: z.string().optional(),
  publishedAt: z.string().optional(),
  updatedAt: z.string().optional(),
  isLatest: z.boolean().optional(),
});

export const MetaSchema = z.object({
  "io.modelcontextprotocol.registry/official": OfficialMetaSchema.optional(),
}).passthrough();

// ---------------------------------------------------------------------------
// Server schemas
// ---------------------------------------------------------------------------

export const ServerSchema = z.object({
  $schema: z.string().optional(),
  name: z.string(),
  description: z.string().optional(),
  title: z.string().optional(),
  version: z.string(),
  repository: RepositorySchema.optional(),
  websiteUrl: z.string().optional(),
  icons: z.array(IconSchema).optional(),
  packages: z.array(PackageSchema).default([]),
  remotes: z.array(RemoteSchema).optional(),
}).passthrough();

export const ServerEntrySchema = z.object({
  server: ServerSchema,
  _meta: MetaSchema.optional(),
}).passthrough();

// ---------------------------------------------------------------------------
// Search / list response schemas
// ---------------------------------------------------------------------------

export const SearchMetadataSchema = z.object({
  nextCursor: z.string().optional(),
  count: z.number().optional(),
});

export const SearchResponseSchema = z.object({
  servers: z.array(ServerEntrySchema),
  metadata: SearchMetadataSchema,
});

// ---------------------------------------------------------------------------
// Server versions schema
// ---------------------------------------------------------------------------

export const ServerVersionSchema = z.object({
  version: z.string(),
  publishedAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

export const ServerVersionsResponseSchema = z.object({
  versions: z.array(ServerVersionSchema),
});
