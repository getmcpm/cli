/**
 * Persistent store for confine profiles (~/.mcpm/guard-confine.yaml + integrity
 * sidecar). This is the SOURCE OF TRUTH for "is server X enrolled in confine" and
 * for its require_confine bit.
 *
 * It FAILS CLOSED on a bad shape / integrity mismatch (modeled on pins.ts, NOT on
 * policy.ts's fail-open `{}` fallback): confine is an enforcement control, so a
 * corrupt store must not silently degrade to "nothing is confined". The caller at
 * spawn (run-inner) treats an unreadable store as "profile absent" and keys the
 * fail-closed decision on the marker's --confine-required flag, so a
 * required-server survives even a wiped store.
 *
 * Issue #19: the sidecar is UNKEYED (integrity, not authenticity) — see
 * store-integrity.ts. A same-user attacker who rewrites this file can recompute
 * the sidecar; the marker content-hash + --confine-required (which live in the
 * IDE config, a different file) are what defend the "attacker wrote ~/.mcpm but
 * not the IDE config" case.
 */

import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import lockfile from "proper-lockfile";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
import { getStorePath } from "../../store/index.js";
import { fileSha, writeFileAtomic } from "../store-integrity.js";
import {
  CONFINE_FORMAT_VERSION,
  ConfineStoreSchema,
  emptyConfineStore,
  type ConfineProfile,
  type ConfineStore,
} from "./profile.js";

const CONFINE_FILENAME = "guard-confine.yaml";
const CONFINE_INTEGRITY_FILENAME = "guard-confine.yaml.integrity";
const SANDBOX_DIRNAME = "sandbox";

export class ConfineIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfineIntegrityError";
  }
}

async function confinePath(): Promise<string> {
  return path.join(await getStorePath(), CONFINE_FILENAME);
}

async function integrityPath(): Promise<string> {
  return path.join(await getStorePath(), CONFINE_INTEGRITY_FILENAME);
}

/** Absolute ~/.mcpm/sandbox root — the parent of every per-server scratch dir. */
export async function confineSandboxRoot(): Promise<string> {
  return path.join(await getStorePath(), SANDBOX_DIRNAME);
}

/**
 * Read + verify the confine store. Returns an empty store if the file does not
 * exist (nothing enrolled). Throws ConfineIntegrityError on a sidecar mismatch,
 * and a plain Error on invalid YAML / shape / format_version — all fail-closed.
 */
export async function readConfineStore(): Promise<ConfineStore> {
  const filePath = await confinePath();
  const sidecarPath = await integrityPath();

  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyConfineStore();
    throw err;
  }

  let sidecar: string | null = null;
  try {
    sidecar = (await readFile(sidecarPath, "utf-8")).trim();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (sidecar !== null && fileSha(raw) !== sidecar) {
    throw new ConfineIntegrityError(
      `guard-confine.yaml integrity check failed. If you intentionally edited it, run ` +
        `\`mcpm guard reset-integrity --confine\`. Otherwise review ~/.mcpm/guard-confine.yaml ` +
        `and ~/.mcpm/guard-events.jsonl for unauthorized changes.`,
    );
  }

  let json: unknown;
  try {
    json = parseYaml(raw) ?? {};
  } catch (err) {
    throw new Error(
      `guard-confine.yaml is not valid YAML (${(err as Error).message}). Remove ` +
        `~/.mcpm/guard-confine.yaml to start fresh or restore from a backup.`,
    );
  }
  const result = ConfineStoreSchema.safeParse(json);
  if (!result.success) {
    throw new Error(
      `guard-confine.yaml has an invalid structure: ${result.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; ")}. Remove ~/.mcpm/guard-confine.yaml to start fresh or restore from a backup.`,
    );
  }
  const parsed = result.data as ConfineStore;
  if (parsed.format_version !== CONFINE_FORMAT_VERSION) {
    throw new Error(
      `guard-confine.yaml format_version mismatch (file: ${parsed.format_version}, expected: ` +
        `${CONFINE_FORMAT_VERSION}). Migration is not yet implemented — file an issue.`,
    );
  }
  return parsed;
}

/** Write the confine store + refresh the integrity sidecar (atomic, lock-serialized). */
export async function writeConfineStore(store: ConfineStore): Promise<void> {
  const filePath = await confinePath();
  const sidecarPath = await integrityPath();
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });

  try {
    await writeFile(filePath, "", { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }
  const release = await lockfile.lock(filePath, {
    retries: { retries: 5, minTimeout: 10, maxTimeout: 200 },
    stale: 5_000,
  });
  try {
    const serialized = stringifyYaml(store);
    await writeFileAtomic(filePath, serialized, "confine");
    await writeFileAtomic(sidecarPath, fileSha(serialized), "confine");
  } finally {
    await release();
  }
}

/**
 * Load one server's profile, or null if it is not enrolled. Propagates a store
 * read error (integrity/corruption) to the caller, which logs it and treats the
 * profile as absent for the spawn decision (keyed on --confine-required).
 */
export async function loadProfile(serverName: string): Promise<ConfineProfile | null> {
  const store = await readConfineStore();
  // Object.hasOwn (not a bare index) to avoid prototype-chain reads, consistent
  // with the SECURITY F13 lookup pattern (the record is Zod-validated too).
  return Object.hasOwn(store.servers, serverName) ? store.servers[serverName] : null;
}

/** Immutable upsert of one server's profile. */
export function withProfile(
  store: ConfineStore,
  serverName: string,
  profile: ConfineProfile,
): ConfineStore {
  return {
    ...store,
    servers: { ...store.servers, [serverName]: profile },
  };
}

/** Immutable removal of one server's profile. */
export function withoutProfile(store: ConfineStore, serverName: string): ConfineStore {
  const next = { ...store.servers };
  delete next[serverName];
  return { ...store, servers: next };
}

/** Regenerate the integrity sidecar from the current file (for reset-integrity). */
export async function resetConfineIntegrity(): Promise<boolean> {
  const filePath = await confinePath();
  const sidecarPath = await integrityPath();
  let raw: string;
  try {
    raw = await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      await unlink(sidecarPath).catch(() => undefined);
      return false;
    }
    throw err;
  }
  await writeFileAtomic(sidecarPath, fileSha(raw), "confine");
  return true;
}
