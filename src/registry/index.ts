/**
 * Registry client — public API barrel export.
 *
 * Consumers import from "src/registry/index.js" (or the compiled "dist/registry/index.js").
 * Internal modules import directly from their sibling file to avoid circular deps.
 */

export { RegistryClient } from "./client.js";
export type { RegistryClientOptions, SearchOptions } from "./client.js";

export {
  RegistryError,
  NetworkError,
  NotFoundError,
  ValidationError,
} from "./errors.js";

export * from "./schemas.js";
export * from "./types.js";

export {
  fetchNpmIntegrity,
  compareIntegrity,
} from "./npm-integrity.js";
export type {
  NpmIntegritySnapshot,
  IntegrityComparison,
} from "./npm-integrity.js";
