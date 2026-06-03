/**
 * Encrypted-at-rest secret storage using Node's built-in crypto.subtle.
 * No native dependencies (contrast: keytar requires node-gyp).
 *
 * Two encryption schemes (security #15):
 *   - keychain ("k1:" tag): AES-GCM key derived via HKDF from a random 32-byte
 *     master key held in the OS credential store (store/os-keychain.ts). The
 *     master key never touches disk, so a copied secrets.enc.json cannot be
 *     decrypted on another machine/account — real exfiltration resistance.
 *   - machine (legacy, untagged): AES-GCM key derived via PBKDF2 from
 *     hostname+username. This is NOT a secret (it is recoverable by anyone who
 *     copies the store file), so it guards only against casual local inspection.
 *     Used as a fallback where no OS keychain is available (headless/CI) and to
 *     decrypt entries written before the keychain upgrade.
 *
 * New secrets use the keychain scheme whenever an OS keychain is available;
 * `migrateToKeychain()` upgrades pre-existing machine-scheme entries.
 *
 * Storage format: ~/.mcpm/secrets.enc.json
 *   { "server/KEY": "k1:<salt_hex>:<iv_hex>:<ct_hex>" }   // keychain scheme
 *   { "server/KEY":    "<salt_hex>:<iv_hex>:<ct_hex>" }   // legacy machine scheme
 *
 * Placeholder format used in config files:
 *   "mcpm:keychain:server/KEY"
 */

import { createHash, randomBytes, webcrypto } from "node:crypto";
import os from "node:os";
import { readJson, writeJson } from "./index.js";
import { withStoreLock } from "./atomic.js";
import { getStoredKey, isSupportedPlatform, storeKey } from "./os-keychain.js";

const STORE_FILE = "secrets.enc.json";
const PLACEHOLDER_PREFIX = "mcpm:keychain:";
const PBKDF2_ITERATIONS = 600_000;

// Scheme tag prefixing keychain-scheme entries: "k1:<salt>:<iv>:<ct>". Legacy
// machine-scheme entries are unprefixed ("<salt>:<iv>:<ct>"), so decrypt() routes
// on the part count — keeping old entries readable after the upgrade (issue #15).
const SCHEME_KEYCHAIN = "k1";
const HKDF_INFO = new TextEncoder().encode("mcpm-secret-store-v1");

// Legacy/fallback machine passphrase. This is NOT a secret: hostname + username
// are recoverable by anyone who copies the store file, so the machine scheme
// guards only against casual local inspection — never file exfiltration. The
// keychain scheme (OS-held master key, below) supersedes it whenever an OS
// credential store is available; this remains for environments without one
// (headless/CI) and to decrypt pre-existing entries (issue #15).
const MACHINE_PASSPHRASE = new TextEncoder().encode(
  `mcpm:${os.hostname()}:${os.userInfo().username}`
);

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

const SAFE_ID_RE = /^[a-zA-Z0-9._-]{1,256}$/;

function assertSafeId(value: string, label: string): void {
  if (!SAFE_ID_RE.test(value)) {
    throw new Error(`Invalid ${label}: "${value}" — must match [a-zA-Z0-9._-], max 256 chars`);
  }
}

function validatedStoreKey(server: string, key: string): string {
  assertSafeId(server, "server");
  assertSafeId(key, "key");
  return `${server}/${key}`;
}

// ---------------------------------------------------------------------------
// Master key (OS credential store) — security #15
// ---------------------------------------------------------------------------
//
// A single random 32-byte key lives in the OS keychain (store/os-keychain.ts);
// per-value AES keys are derived from it via HKDF. Because the master key is
// never written to ~/.mcpm, a copied secrets.enc.json cannot be decrypted on
// another machine/account. When no OS keychain is available, encrypt() falls
// back to the machine scheme below.

let _masterKey: { value: Buffer | null } | undefined;

/** Read the stored master key (never creates one); memoized per process. */
async function readMasterKey(): Promise<Buffer | null> {
  if (_masterKey) return _masterKey.value;
  const value = await getStoredKey();
  _masterKey = { value };
  return value;
}

/**
 * Return the master key, creating and persisting a fresh random one if none
 * exists yet and the platform has a usable credential store. Creation runs
 * under the store lock so two concurrent first-writes cannot generate two keys
 * and leave one writer's secret undecryptable.
 */
async function getOrCreateMasterKey(): Promise<Buffer | null> {
  const existing = await readMasterKey();
  if (existing) return existing;
  if (!isSupportedPlatform()) return null;
  return withStoreLock(async () => {
    const raced = await getStoredKey(); // another process may have just created it
    if (raced) {
      _masterKey = { value: raced };
      return raced;
    }
    const key = randomBytes(32);
    // If the keychain write fails, memoize null: this session falls back to the
    // machine scheme for the rest of its life (no retry). That is the safe,
    // honest outcome — activeSecretBackend() will report "machine-key" and
    // `secrets set` warns the user — rather than half-using an unpersisted key.
    const value = (await storeKey(key)) ? key : null;
    _masterKey = { value };
    return value;
  });
}

// ---------------------------------------------------------------------------
// Key derivation — keychain scheme (HKDF) and machine scheme (PBKDF2)
// ---------------------------------------------------------------------------

// HKDF importKey is cheap but stable per master key; cache it per-process.
let _hkdfMaterial: { key: Buffer; material: Promise<webcrypto.CryptoKey> } | undefined;

function hkdfMaterial(masterKey: Buffer): Promise<webcrypto.CryptoKey> {
  if (!_hkdfMaterial || !_hkdfMaterial.key.equals(masterKey)) {
    _hkdfMaterial = {
      key: masterKey,
      material: webcrypto.subtle.importKey("raw", masterKey, "HKDF", false, ["deriveKey"]),
    };
  }
  return _hkdfMaterial.material;
}

async function deriveKeychainKey(masterKey: Buffer, salt: Uint8Array): Promise<webcrypto.CryptoKey> {
  const material = await hkdfMaterial(masterKey);
  return webcrypto.subtle.deriveKey(
    { name: "HKDF", salt, info: HKDF_INFO, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Cache the PBKDF2 importKey step — it is cheap but never varies within a
// process. The expensive derivation still runs per value (random per-value salt).
let _keyMaterialPromise: Promise<webcrypto.CryptoKey> | null = null;

function getMachineKeyMaterial(): Promise<webcrypto.CryptoKey> {
  if (!_keyMaterialPromise) {
    _keyMaterialPromise = webcrypto.subtle.importKey(
      "raw",
      MACHINE_PASSPHRASE,
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
  }
  return _keyMaterialPromise;
}

async function deriveMachineKey(salt: Uint8Array): Promise<webcrypto.CryptoKey> {
  const keyMaterial = await getMachineKeyMaterial();
  return webcrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Reset memoized master-key / HKDF state. Test-only. @internal */
export function _resetMasterKeyCache(): void {
  _masterKey = undefined;
  _hkdfMaterial = undefined;
}

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

const hex = (buf: ArrayBuffer | Uint8Array): string =>
  Buffer.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf)).toString("hex");

async function encrypt(plaintext: string): Promise<string> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const masterKey = await getOrCreateMasterKey();
  const key = masterKey
    ? await deriveKeychainKey(masterKey, salt)
    : await deriveMachineKey(salt);
  const cipherBuf = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  const body = [hex(salt), hex(iv), hex(cipherBuf)].join(":");
  // Keychain-scheme entries are tagged so decrypt() can route; machine-scheme
  // entries stay in the legacy unprefixed format for backward compatibility.
  return masterKey ? `${SCHEME_KEYCHAIN}:${body}` : body;
}

async function decryptWith(
  key: webcrypto.CryptoKey,
  ivHex: string,
  cipherHex: string
): Promise<string> {
  const plainBuf = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivHex, "hex") },
    key,
    Buffer.from(cipherHex, "hex")
  );
  return new TextDecoder().decode(plainBuf);
}

async function decrypt(stored: string): Promise<string> {
  const parts = stored.split(":");
  // Keychain scheme: "k1:<salt>:<iv>:<ct>"
  if (parts.length === 4 && parts[0] === SCHEME_KEYCHAIN) {
    const [, saltHex, ivHex, cipherHex] = parts;
    const masterKey = await readMasterKey();
    if (!masterKey) {
      throw new Error(
        "Cannot decrypt: this secret is protected by the OS keychain master key, " +
          "which is unavailable on this machine/account (or the keychain entry was removed)."
      );
    }
    const key = await deriveKeychainKey(masterKey, Buffer.from(saltHex, "hex"));
    return decryptWith(key, ivHex, cipherHex);
  }
  // Legacy machine scheme: "<salt>:<iv>:<ct>"
  if (parts.length === 3) {
    const [saltHex, ivHex, cipherHex] = parts;
    const key = await deriveMachineKey(Buffer.from(saltHex, "hex"));
    return decryptWith(key, ivHex, cipherHex);
  }
  throw new Error("Invalid ciphertext format");
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

async function readStore(): Promise<Record<string, string>> {
  return (await readJson<Record<string, string>>(STORE_FILE)) ?? {};
}

// Decrypt a single stored value identified by its store key against an
// already-loaded store snapshot. Shared by the unlocked per-key getSecret and
// the locked snapshot resolver so both decode entries identically.
async function decryptFromSnapshot(
  store: Record<string, string>,
  sk: string
): Promise<string | null> {
  const stored = store[sk];
  return stored ? decrypt(stored) : null;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function setSecret(server: string, key: string, value: string): Promise<void> {
  const sk = validatedStoreKey(server, key);
  // Encrypt outside the lock (it does not depend on stored state) to keep the
  // critical section short, then read-merge-write atomically under the lock.
  const encrypted = await encrypt(value);
  await withStoreLock(async () => {
    const store = await readStore();
    await writeJson(STORE_FILE, { ...store, [sk]: encrypted });
  });
}

/**
 * Store multiple secrets for one server in a single read-modify-write, so the
 * batch is all-or-nothing: either every value is persisted or none is (no
 * orphaned half-written secrets if one encrypt fails — security review MED-1).
 */
export async function setSecrets(
  server: string,
  values: Record<string, string>
): Promise<void> {
  // Encrypt every value first (no dependency on stored state), then read-merge-
  // write atomically under the lock so a concurrent writer cannot lost-update
  // this batch.
  const encrypted: Record<string, string> = {};
  for (const [key, value] of Object.entries(values)) {
    encrypted[validatedStoreKey(server, key)] = await encrypt(value);
  }
  await withStoreLock(async () => {
    const store = await readStore();
    await writeJson(STORE_FILE, { ...store, ...encrypted });
  });
}

// Intentionally UNLOCKED: a read-only single-key lookup. It accepts eventual
// consistency (it may observe a concurrent writer's snapshot before or after a
// mutation, never a torn one — writeJson swaps the file atomically via rename).
// The consistency-sensitive path is resolveEnvPlaceholders, which takes the
// lock and reads one snapshot for all keys.
export async function getSecret(server: string, key: string): Promise<string | null> {
  const sk = validatedStoreKey(server, key);
  return decryptFromSnapshot(await readStore(), sk);
}

export async function deleteSecret(server: string, key: string): Promise<void> {
  const sk = validatedStoreKey(server, key);
  await withStoreLock(async () => {
    const store = await readStore();
    if (!(sk in store)) return;
    const { [sk]: _removed, ...rest } = store;
    await writeJson(STORE_FILE, rest);
  });
}

// Intentionally UNLOCKED: read-only key enumeration, eventual consistency.
export async function listSecretKeys(server: string): Promise<string[]> {
  assertSafeId(server, "server");
  const prefix = `${server}/`;
  return Object.keys(await readStore())
    .filter((k) => k.startsWith(prefix))
    .map((k) => k.slice(prefix.length));
}

/** Produces the placeholder string stored in config files. */
export function toPlaceholder(server: string, key: string): string {
  return `${PLACEHOLDER_PREFIX}${server}/${key}`;
}

/** Parses a placeholder string. Returns null if not a placeholder. */
export function parsePlaceholder(value: string): { server: string; key: string } | null {
  if (!value.startsWith(PLACEHOLDER_PREFIX)) return null;
  const rest = value.slice(PLACEHOLDER_PREFIX.length);
  const slashIdx = rest.indexOf("/");
  if (slashIdx === -1) return null;
  return { server: rest.slice(0, slashIdx), key: rest.slice(slashIdx + 1) };
}

/**
 * Resolve any `mcpm:keychain:server/KEY` placeholder values in an env map to
 * their decrypted secrets. Non-placeholder values pass through unchanged;
 * `undefined` values are dropped. Throws if a placeholder references a secret
 * that is not stored.
 *
 * The decrypted values exist only in the returned in-memory object — they are
 * never written to disk. `mcpm guard run --inner` calls this to inject secrets
 * into a wrapped server's child process without storing plaintext in client
 * config files.
 *
 * Reads the store as a single CONSISTENT SNAPSHOT under `withStoreLock`: all
 * placeholders are resolved against one read taken while holding the same lock
 * the write paths (setSecret/setSecrets/deleteSecret) hold. This closes the
 * read-after-delete race where a concurrent `secrets delete` during guard
 * startup made a per-key unlocked lookup observe a torn state and throw "Secret
 * not found" — the exact race the lock was added to prevent. This is the only
 * caller (guard/run-inner.ts), invoked at the top level and NOT from inside an
 * already-held store lock, so acquiring the lock here cannot self-deadlock.
 */
export async function resolveEnvPlaceholders(
  env: NodeJS.ProcessEnv
): Promise<Record<string, string>> {
  // Parse placeholders up front so the locked critical section is just one read
  // plus decryption — no validation or iteration over non-placeholder values.
  const passthrough: Record<string, string> = {};
  const placeholders: Array<{ name: string; server: string; key: string }> = [];
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const placeholder = parsePlaceholder(value);
    if (placeholder === null) {
      passthrough[name] = value;
      continue;
    }
    placeholders.push({ name, ...placeholder });
  }

  // No secrets to resolve — skip the lock entirely.
  if (placeholders.length === 0) return passthrough;

  return withStoreLock(async () => {
    const store = await readStore();
    const resolved: Record<string, string> = { ...passthrough };
    for (const { name, server, key } of placeholders) {
      const sk = validatedStoreKey(server, key);
      const secret = await decryptFromSnapshot(store, sk);
      if (secret === null) {
        throw new Error(
          `Secret "${server}/${key}" not found. ` +
            `Run \`mcpm secrets set ${server} ${key}\` to store it.`
        );
      }
      resolved[name] = secret;
    }
    return resolved;
  });
}

/**
 * Derive a keychain-safe server id from a (possibly slash-containing) server
 * name. Registry ids like "io.github.owner/repo" contain `/`, which is invalid
 * for a keychain id (assertSafeId) and would break placeholder parsing (which
 * splits on the first `/`).
 *
 * The sanitised prefix keeps the id human-recognisable; a sha256 suffix makes
 * the mapping INJECTIVE, so two names that differ only in unsafe characters
 * (e.g. "owner/repo" vs "owner_repo") can never collide into one secret
 * namespace (security review CRIT-1). Deterministic: the same name always maps
 * to the same id, so a placeholder written at install resolves at launch.
 */
export function deriveKeychainId(name: string): string {
  const sanitized = name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 200);
  const hash = createHash("sha256").update(name).digest("hex").slice(0, 12);
  return `${sanitized}-${hash}`;
}

/**
 * List all stored secrets grouped by server name. Returns only key names —
 * decrypted values are never read or returned.
 *
 * Intentionally UNLOCKED: read-only enumeration, eventual consistency.
 */
export async function listAll(): Promise<Record<string, string[]>> {
  const store = await readStore();
  const grouped: Record<string, string[]> = {};
  for (const storeKey of Object.keys(store)) {
    const slashIdx = storeKey.indexOf("/");
    if (slashIdx === -1) continue;
    const server = storeKey.slice(0, slashIdx);
    const key = storeKey.slice(slashIdx + 1);
    (grouped[server] ??= []).push(key);
  }
  return grouped;
}

// ---------------------------------------------------------------------------
// Backend status + migration (security #15)
// ---------------------------------------------------------------------------

/**
 * Which backend protects secrets written right now — reflects reality, not just
 * platform capability. Returns "os-keychain" only when a master key is actually
 * present (so it is accurate after a `setSecret`, even if a keychain write had
 * silently failed and fell back to the machine scheme).
 */
export async function activeSecretBackend(): Promise<"os-keychain" | "machine-key"> {
  return (await readMasterKey()) !== null ? "os-keychain" : "machine-key";
}

/**
 * Re-encrypt every legacy machine-scheme entry under the OS keychain master
 * key, so existing secrets gain the same exfiltration resistance as new ones.
 *
 * No-op (`usingKeychain: false`) when no OS keychain is available. Per-entry
 * failures are isolated: a legacy entry this machine key can no longer decrypt
 * (e.g. written on a different machine) is counted in `failed` and left
 * untouched rather than aborting the whole migration.
 */
export async function migrateToKeychain(): Promise<{
  migrated: number;
  failed: number;
  total: number;
  usingKeychain: boolean;
}> {
  const masterKey = await getOrCreateMasterKey();
  if (!masterKey) return { migrated: 0, failed: 0, total: 0, usingKeychain: false };
  return withStoreLock(async () => {
    const store = await readStore();
    const entries = Object.entries(store);
    const next: Record<string, string> = {};
    let migrated = 0;
    let failed = 0;
    for (const [sk, value] of entries) {
      const isLegacy = value.split(":").length === 3;
      if (!isLegacy) {
        next[sk] = value; // already keychain-scheme (or unknown) — leave as-is
        continue;
      }
      try {
        const plain = await decrypt(value); // legacy machine scheme
        next[sk] = await encrypt(plain); // re-encrypt under the keychain master key
        migrated++;
      } catch {
        next[sk] = value; // undecryptable legacy entry — leave untouched
        failed++;
      }
    }
    if (migrated > 0) await writeJson(STORE_FILE, next);
    return { migrated, failed, total: entries.length, usingKeychain: true };
  });
}

/**
 * How secret-flagged env vars are persisted.
 * - "plaintext": written directly into the client config (legacy default).
 * - "keychain":  stored AES-GCM-encrypted; config gets a `mcpm:keychain:…`
 *   placeholder that mcpm guard resolves at launch.
 */
export type SecretsMode = "plaintext" | "keychain";

/**
 * Resolve a server's env map for writing to a client config under the given
 * secrets mode. In "keychain" mode, every key for which `isSecret(key)` is true
 * is stored encrypted via `setSecret` and replaced with a `mcpm:keychain:…`
 * placeholder; all other values pass through. In "plaintext" mode the input is
 * returned unchanged. This is the single place the "no plaintext secret in
 * config" invariant is enforced — install and up both go through it.
 *
 * Throws if keychain mode is requested without a `setSecret` implementation.
 */
export async function applyKeychainSecrets(opts: {
  serverName: string;
  resolvedEnv: Record<string, string>;
  isSecret: (key: string) => boolean;
  mode: SecretsMode;
  setSecrets?: (server: string, values: Record<string, string>) => Promise<void>;
}): Promise<{ env: Record<string, string>; storedCount: number }> {
  if (opts.mode !== "keychain") {
    return { env: opts.resolvedEnv, storedCount: 0 };
  }
  if (!opts.setSecrets) {
    throw new Error("Keychain secret storage is unavailable.");
  }
  const keychainId = deriveKeychainId(opts.serverName);
  const env: Record<string, string> = {};
  const toStore: Record<string, string> = {};
  for (const [key, value] of Object.entries(opts.resolvedEnv)) {
    if (opts.isSecret(key)) {
      toStore[key] = value;
      env[key] = toPlaceholder(keychainId, key);
    } else {
      env[key] = value;
    }
  }
  const storedCount = Object.keys(toStore).length;
  // Persist all secrets in one atomic batch BEFORE returning the env that the
  // caller writes to config — so we never write a placeholder for a secret that
  // failed to store (all-or-nothing; security review MED-1).
  if (storedCount > 0) {
    await opts.setSecrets(keychainId, toStore);
  }
  return { env, storedCount };
}

/**
 * Return the keys of `env` whose value is a `mcpm:keychain:…` placeholder.
 * Used by `mcpm guard disable` to warn about secrets that will no longer
 * resolve once guard stops wrapping the server.
 */
export function placeholderEnvKeys(env: Record<string, string> | undefined): string[] {
  if (!env) return [];
  return Object.entries(env)
    .filter(([, v]) => typeof v === "string" && parsePlaceholder(v) !== null)
    .map(([k]) => k);
}
