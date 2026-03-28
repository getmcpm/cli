/**
 * TypeScript types derived from Zod schemas.
 * Never define types manually here — always infer from schemas.ts.
 */

import type { z } from "zod";
import type {
  EnvVarSchema,
  IconSchema,
  MetaSchema,
  OfficialMetaSchema,
  PackageSchema,
  RemoteHeaderSchema,
  RemoteSchema,
  RepositorySchema,
  SearchMetadataSchema,
  SearchResponseSchema,
  ServerEntrySchema,
  ServerSchema,
  ServerVersionSchema,
  ServerVersionsResponseSchema,
  TransportSchema,
} from "./schemas.js";

export type Repository = z.infer<typeof RepositorySchema>;
export type Icon = z.infer<typeof IconSchema>;
export type EnvVar = z.infer<typeof EnvVarSchema>;
export type Transport = z.infer<typeof TransportSchema>;
export type Package = z.infer<typeof PackageSchema>;
export type RemoteHeader = z.infer<typeof RemoteHeaderSchema>;
export type Remote = z.infer<typeof RemoteSchema>;
export type OfficialMeta = z.infer<typeof OfficialMetaSchema>;
export type Meta = z.infer<typeof MetaSchema>;
export type Server = z.infer<typeof ServerSchema>;
export type ServerEntry = z.infer<typeof ServerEntrySchema>;
export type SearchMetadata = z.infer<typeof SearchMetadataSchema>;
export type SearchResult = z.infer<typeof SearchResponseSchema>;
export type ServerVersion = z.infer<typeof ServerVersionSchema>;
export type ServerVersionsResponse = z.infer<
  typeof ServerVersionsResponseSchema
>;
