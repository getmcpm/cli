/**
 * Zod schemas — single source of truth for all registry API types.
 *
 * All TypeScript types are derived from these via z.infer<>.
 * Validated against the official MCP Registry API v0.1 response shape.
 */

import { z } from "zod";

// Length ceilings for external registry free-text. The registry API is an
// untrusted boundary; the Tier-1 scanner and the terminal renderer walk these
// strings, so an oversized field inflates their cost — the ReDoS fix bounds
// per-regex work, these bound the input length itself. Ceilings are generous
// (far above any legitimate value) on purpose: safeParse drops the WHOLE
// page/server on a single over-ceiling field, so they must never clip real
// data — only deny a multi-MB DoS payload.
const MAX_NAME = 1024; // names, identifiers, versions, types, statuses, timestamps
const MAX_URL = 8192; // real URLs + opaque tokens (icon.src may be a large data: URI — left uncapped)
const MAX_TEXT = 65536; // free-text: descriptions, titles, status messages, defaults

// ---------------------------------------------------------------------------
// Sub-schemas
// ---------------------------------------------------------------------------

export const RepositorySchema = z.object({
  url: z.string().max(MAX_URL).optional(),
  source: z.string().max(MAX_NAME).optional(),
  id: z.union([z.string().max(MAX_NAME), z.number()]).optional(),
  subfolder: z.string().max(MAX_NAME).optional(),
});

export const IconSchema = z.object({
  // src is a URI or URL — may legitimately be a large base64 data: URI (an
  // embedded icon), and it is never regex-scanned or rendered to the terminal,
  // so it is intentionally left uncapped (a length cap here would drop pages
  // carrying data-URI icons for no security gain).
  src: z.string(),
  mimeType: z.string().max(MAX_NAME).optional(),
});

export const EnvVarSchema = z.object({
  name: z.string().max(MAX_NAME),
  description: z.string().max(MAX_TEXT).optional(),
  isRequired: z.boolean().optional(),
  isSecret: z.boolean().optional(),
  default: z.string().max(MAX_TEXT).optional(),
});

export const TransportSchema = z.object({
  type: z.string().max(MAX_NAME),
});

/**
 * Argument — the official MCP Registry Argument type, shared by runtimeArguments
 * (and packageArguments). Two forms: named ({type:"named",name:"--rm",value?,...})
 * and positional ({type:"positional",valueHint:"directory",value?,...}). Every
 * field is optional so the live named shape ({type:"named",name:"-i"} — no `value`)
 * parses; .passthrough() keeps unmodeled fields (description, format, default,
 * isRepeated, isRequired) and lets unknown future arg types pass through rather
 * than hard-failing (same forward-compat philosophy as registryType above).
 */
export const ArgumentSchema = z.union([
  z.string().max(MAX_TEXT),
  z
    .object({
      type: z.string().max(MAX_NAME).optional(),
      name: z.string().max(MAX_NAME).optional(),
      value: z.string().max(MAX_TEXT).optional(),
      valueHint: z.string().max(MAX_TEXT).optional(),
    })
    .passthrough(),
]);

/**
 * Package entry — discriminated union on registryType.
 * We use z.string() for registryType so unknown future types pass through
 * rather than hard-failing, while still retaining the typed field.
 */
export const PackageSchema = z.object({
  registryType: z.string().max(MAX_NAME),
  identifier: z.string().max(MAX_NAME),
  version: z.string().max(MAX_NAME).optional(),
  transport: TransportSchema.optional(),
  environmentVariables: z.array(EnvVarSchema).default([]),
  runtimeArguments: z.array(ArgumentSchema).optional(),
});

export const RemoteHeaderSchema = z.object({
  name: z.string().max(MAX_NAME),
  isRequired: z.boolean().optional(),
  isSecret: z.boolean().optional(),
  description: z.string().max(MAX_TEXT).optional(),
});

export const RemoteSchema = z.object({
  type: z.string().max(MAX_NAME),
  url: z.string().url().max(MAX_URL),
  headers: z.array(RemoteHeaderSchema).default([]),
});

export const OfficialMetaSchema = z.object({
  // Server lifecycle status — the registry enum is "active" | "deprecated" |
  // "deleted" (kept as z.string() for forward-compat). statusMessage carries the
  // registry's optional human explanation (e.g. deprecation/removal reason).
  status: z.string().max(MAX_NAME).optional(),
  statusMessage: z.string().max(MAX_TEXT).optional(),
  publishedAt: z.string().max(MAX_NAME).optional(),
  updatedAt: z.string().max(MAX_NAME).optional(),
  isLatest: z.boolean().optional(),
});

export const MetaSchema = z.object({
  "io.modelcontextprotocol.registry/official": OfficialMetaSchema.optional(),
}).passthrough();

// ---------------------------------------------------------------------------
// Server schemas
// ---------------------------------------------------------------------------

export const ServerSchema = z.object({
  $schema: z.string().max(MAX_URL).optional(),
  name: z.string().max(MAX_NAME),
  description: z.string().max(MAX_TEXT).optional(),
  title: z.string().max(MAX_NAME).optional(),
  version: z.string().max(MAX_NAME),
  repository: RepositorySchema.optional(),
  websiteUrl: z.string().max(MAX_URL).optional(),
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
  nextCursor: z.string().max(MAX_URL).optional(),
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
  version: z.string().max(MAX_NAME),
  publishedAt: z.string().max(MAX_NAME).optional(),
  updatedAt: z.string().max(MAX_NAME).optional(),
});

export const ServerVersionsResponseSchema = z.object({
  versions: z.array(ServerVersionSchema),
});
