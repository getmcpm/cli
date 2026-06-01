/**
 * Encrypted-at-rest secret storage using Node's built-in crypto.subtle + PBKDF2.
 *
 * No native dependencies (contrast: keytar requires node-gyp).
 * AES-GCM with PBKDF2-derived key (600,000 iterations, SHA-256, random per-value salt).
 *
 * Storage format: ~/.mcpm/secrets.enc.json
 *   { "server/KEY": "<salt_hex>:<iv_hex>:<ciphertext_hex>" }
 *
 * Placeholder format used in config files:
 *   "mcpm:keychain:server/KEY"
 *
 * Security posture: protects against casual inspection of the store file.
 * High-value credentials should use the OS keychain (keytar) rather than this layer.
 */

import { randomBytes, webcrypto } from "node:crypto";
import os from "node:os";
import { readJson, writeJson } from "./index.js";

const STORE_FILE = "secrets.enc.json";
const PLACEHOLDER_PREFIX = "mcpm:keychain:";
const PBKDF2_ITERATIONS = 600_000;

// Computed once per process — hostname and username never change within a session.
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
// Key derivation (PBKDF2 with per-value salt; importKey cached per-process)
// ---------------------------------------------------------------------------

// Cache the importKey step — it is cheap but never varies within a process.
// The expensive PBKDF2 still runs per value because each value has its own random salt.
let _keyMaterialPromise: Promise<webcrypto.CryptoKey> | null = null;

function getKeyMaterial(): Promise<webcrypto.CryptoKey> {
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

async function deriveKey(salt: Uint8Array): Promise<webcrypto.CryptoKey> {
  const keyMaterial = await getKeyMaterial();
  return webcrypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

async function encrypt(plaintext: string): Promise<string> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(salt);
  const cipherBuf = await webcrypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );
  return [
    Buffer.from(salt).toString("hex"),
    Buffer.from(iv).toString("hex"),
    Buffer.from(cipherBuf).toString("hex"),
  ].join(":");
}

async function decrypt(stored: string): Promise<string> {
  const parts = stored.split(":");
  if (parts.length !== 3) throw new Error("Invalid ciphertext format");
  const [saltHex, ivHex, cipherHex] = parts;
  const key = await deriveKey(Buffer.from(saltHex, "hex"));
  const plainBuf = await webcrypto.subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(ivHex, "hex") },
    key,
    Buffer.from(cipherHex, "hex")
  );
  return new TextDecoder().decode(plainBuf);
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

async function readStore(): Promise<Record<string, string>> {
  return (await readJson<Record<string, string>>(STORE_FILE)) ?? {};
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export async function setSecret(server: string, key: string, value: string): Promise<void> {
  const sk = validatedStoreKey(server, key);
  const store = await readStore();
  await writeJson(STORE_FILE, { ...store, [sk]: await encrypt(value) });
}

export async function getSecret(server: string, key: string): Promise<string | null> {
  const sk = validatedStoreKey(server, key);
  const stored = (await readStore())[sk];
  return stored ? decrypt(stored) : null;
}

export async function deleteSecret(server: string, key: string): Promise<void> {
  const sk = validatedStoreKey(server, key);
  const store = await readStore();
  if (!(sk in store)) return;
  const { [sk]: _removed, ...rest } = store;
  await writeJson(STORE_FILE, rest);
}

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
 */
export async function resolveEnvPlaceholders(
  env: NodeJS.ProcessEnv
): Promise<Record<string, string>> {
  const resolved: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const placeholder = parsePlaceholder(value);
    if (placeholder === null) {
      resolved[name] = value;
      continue;
    }
    const secret = await getSecret(placeholder.server, placeholder.key);
    if (secret === null) {
      throw new Error(
        `Secret "${placeholder.server}/${placeholder.key}" not found. ` +
          `Run \`mcpm secrets set ${placeholder.server} ${placeholder.key}\` to store it.`
      );
    }
    resolved[name] = secret;
  }
  return resolved;
}

/**
 * Derive a keychain-safe server id from a (possibly slash-containing) server
 * name. Registry ids like "io.github.owner/repo" contain `/`, which is invalid
 * for a keychain id (assertSafeId) and would break placeholder parsing (which
 * splits on the first `/`). Replaces every character outside [a-zA-Z0-9._-]
 * with `_` and truncates to 256 chars. Deterministic: the same name always
 * maps to the same id, so a placeholder written at install resolves at launch.
 */
export function deriveKeychainId(name: string): string {
  return name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 256);
}

/**
 * List all stored secrets grouped by server name. Returns only key names —
 * decrypted values are never read or returned.
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
  setSecret?: (server: string, key: string, value: string) => Promise<void>;
}): Promise<{ env: Record<string, string>; storedCount: number }> {
  if (opts.mode !== "keychain") {
    return { env: opts.resolvedEnv, storedCount: 0 };
  }
  if (!opts.setSecret) {
    throw new Error("Keychain secret storage is unavailable.");
  }
  const keychainId = deriveKeychainId(opts.serverName);
  const env: Record<string, string> = {};
  let storedCount = 0;
  for (const [key, value] of Object.entries(opts.resolvedEnv)) {
    if (opts.isSecret(key)) {
      await opts.setSecret(keychainId, key, value);
      env[key] = toPlaceholder(keychainId, key);
      storedCount += 1;
    } else {
      env[key] = value;
    }
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
