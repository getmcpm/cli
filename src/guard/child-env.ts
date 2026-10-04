/** Server settings that must never configure the guard's own startup/runtime. */
export const CHILD_ENV_FIELD = "MCPM_GUARD_CHILD_ENV";

function isLoaderEnvKey(key: string): boolean {
  const name = key.toUpperCase();
  // Include startup file output/cache controls as well as code loaders.
  // NODE_ENV is an ordinary application setting, not a Node startup control.
  return ["NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_ICU_DATA",
    "NODE_V8_COVERAGE", "NODE_COMPILE_CACHE", "NODE_REDIRECT_WARNINGS",
    "NODE_DEBUG", "NODE_DEBUG_NATIVE", "NODE_TLS_REJECT_UNAUTHORIZED"].includes(name) ||
    name === "OPENSSL_CONF" || name === "OPENSSL_MODULES" ||
    name === "GLIBC_TUNABLES" || name.startsWith("LD_") ||
    name.startsWith("DYLD_");
}

export function isChildOnlyEnvKey(key: string): boolean {
  const name = key.toUpperCase();
  return isLoaderEnvKey(key) || name.startsWith("MCPM_") ||
    ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "PATH"].includes(name);
}

export function wrapChildEnv(env: Record<string, string>): Record<string, string> {
  if (Object.keys(env).some((key) => key.toUpperCase() === CHILD_ENV_FIELD)) {
    throw new Error(`Cannot wrap a server declaring reserved ${CHILD_ENV_FIELD}`);
  }
  const child: Record<string, string> = Object.create(null);
  const wrapper: Record<string, string> = Object.create(null);
  for (const [key, value] of Object.entries(env)) {
    (isChildOnlyEnvKey(key) ? child : wrapper)[key] = value;
  }
  if (Object.keys(child).length > 0) wrapper[CHILD_ENV_FIELD] = JSON.stringify(child);
  return wrapper;
}

/** Decode only the exact declared settings; never mutate the guard process env. */
export function readChildEnv(
  env: NodeJS.ProcessEnv,
  declaredKeys: readonly string[],
  allowLegacy = false,
  allowAmbient = false,
): Record<string, string> {
  const keys = declaredKeys.filter(isChildOnlyEnvKey);
  const payload = env[CHILD_ENV_FIELD];
  if (payload === undefined) {
    if (keys.length === 0 || (allowLegacy && keys.every((key) => (env[key] !== undefined && (!allowAmbient || isLoaderEnvKey(key)))))) return {};
    throw new Error("Missing child environment transport; disable then enable the guard again");
  }
  let decoded: unknown;
  try { decoded = JSON.parse(payload); } catch { throw new Error("Malformed child environment transport"); }
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("Malformed child environment transport");
  }
  const entries = Object.entries(decoded);
  if (keys.some((key) => key.toUpperCase() === CHILD_ENV_FIELD) ||
      entries.length !== keys.length || entries.some(([key, value]) =>
        !keys.includes(key) || typeof value !== "string" || value.includes("\0") ||
        (env[key] !== undefined && (!allowAmbient || isLoaderEnvKey(key))))) {
    throw new Error("Child environment transport does not match declared settings");
  }
  return Object.fromEntries(entries) as Record<string, string>;
}

/** Apply child settings without leaving competing Windows aliases in the baseline. */
export function restoreChildEnv(
  baseline: NodeJS.ProcessEnv,
  declared: Record<string, string>,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  const overridden = new Set(Object.keys(declared).map((key) => key.toUpperCase()));
  return {
    ...Object.fromEntries(Object.entries(baseline).filter(([key]) =>
      platform !== "win32" || !overridden.has(key.toUpperCase()))),
    ...declared,
  };
}
