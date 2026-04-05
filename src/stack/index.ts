/**
 * Stack module — public API surface.
 */

export {
  StackFileSchema,
  LockFileSchema,
  parseStackFile,
  parseLockFile,
  serializeYaml,
  isRegistryServer,
  isUrlServer,
  isLockedRegistryServer,
} from "./schema.js";

export type {
  StackFile,
  StackServer,
  StackEnvVar,
  Policy,
  LockFile,
  LockedServer,
  TrustSnapshot,
} from "./schema.js";

export { resolveVersion, resolveWithSingleVersion } from "./resolve.js";
export type { ResolveResult } from "./resolve.js";

export { checkTrustPolicy } from "./policy.js";
export type { PolicyCheckInput, PolicyResult } from "./policy.js";

export { parseEnvFile, parseEnvString } from "./env.js";
export type { EnvParseResult } from "./env.js";
