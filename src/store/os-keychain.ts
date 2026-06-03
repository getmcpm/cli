/**
 * Zero-native-dependency access to the operating system's credential store.
 *
 * The secret store (store/keychain.ts) holds a single random 32-byte *master
 * key* here; every stored secret is AES-GCM-encrypted with a subkey derived
 * from it. Keeping the master key in the OS credential store — not on disk —
 * is what makes a copied `~/.mcpm/secrets.enc.json` undecryptable off-machine
 * (security issue #15).
 *
 * No native modules (no `keytar`/node-gyp). We shell out to the platform's
 * built-in tooling:
 *   - macOS:   `security` (login Keychain)            — generic password item
 *   - Linux:   `secret-tool` (libsecret/Secret Service) — schema attributes
 *   - Windows: DPAPI via PowerShell `ProtectedData`   — blob in ~/.mcpm
 *
 * Every operation is best-effort: if the platform tool is missing, the Secret
 * Service is unavailable (headless Linux, CI), or any call fails, the function
 * resolves to "unavailable"/null and the caller falls back to the legacy
 * machine-derived key (casual-inspection only — see store/keychain.ts).
 *
 * Set `MCPM_DISABLE_OS_KEYCHAIN=1` to force the fallback (used by the test
 * suite so it never touches the developer's real Keychain, and available to
 * users who prefer not to use the OS store).
 */

import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getStorePath } from "./index.js";

const SERVICE = "mcpm";
const ACCOUNT = "secret-store-master-key";
const DPAPI_BLOB_FILE = "master-key.dpapi";
const EXEC_TIMEOUT_MS = 5_000;

/** Result of a child-process run. `code === null` means spawn failed (ENOENT). */
interface RunResult {
  code: number | null;
  stdout: string;
  stderr: string;
}

/**
 * Run a command to completion, optionally feeding `input` to stdin. Never
 * rejects: a missing binary (ENOENT) or any spawn error resolves to
 * `{ code: null }` so callers treat it uniformly as "unavailable".
 */
function run(
  command: string,
  args: string[],
  opts: { input?: string; env?: NodeJS.ProcessEnv } = {}
): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      timeout: EXEC_TIMEOUT_MS,
      env: opts.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", () => resolve({ code: null, stdout, stderr }));
    child.on("close", (code) => resolve({ code, stdout, stderr }));
    if (opts.input !== undefined) {
      child.stdin.on("error", () => {
        /* child may have exited before stdin flush; swallow EPIPE */
      });
      child.stdin.end(opts.input);
    } else {
      child.stdin.end();
    }
  });
}

/** True on a platform we know how to drive (and not explicitly disabled). */
export function isSupportedPlatform(): boolean {
  if (process.env.MCPM_DISABLE_OS_KEYCHAIN === "1") return false;
  return (
    process.platform === "darwin" ||
    process.platform === "linux" ||
    process.platform === "win32"
  );
}

// ---------------------------------------------------------------------------
// macOS — security(1) generic-password items in the login Keychain
// ---------------------------------------------------------------------------

async function darwinGet(): Promise<Buffer | null> {
  // -w prints only the password; exit 44 when the item does not exist.
  const r = await run("security", [
    "find-generic-password",
    "-a",
    ACCOUNT,
    "-s",
    SERVICE,
    "-w",
  ]);
  if (r.code !== 0) return null;
  return decodeKey(r.stdout.trim());
}

async function darwinStore(keyB64: string): Promise<boolean> {
  // -U updates the item if it already exists instead of erroring.
  //
  // Tradeoff: `security` has no reliable non-interactive stdin path for the
  // password, so the (base64) master key is passed in argv and is briefly
  // visible to a *same-user* `ps` during the child's lifetime. This is a narrow,
  // write-only window: the read path (darwinGet) returns the key on stdout to
  // this parent only, and cross-user argv is not readable. A same-user attacker
  // who can `ps` can already read this process's memory, so this does not widen
  // the trust boundary the keychain establishes (off-machine file exfiltration).
  const r = await run("security", [
    "add-generic-password",
    "-a",
    ACCOUNT,
    "-s",
    SERVICE,
    "-U",
    "-w",
    keyB64,
  ]);
  return r.code === 0;
}

// ---------------------------------------------------------------------------
// Linux — secret-tool (libsecret). Value is read from / written to stdin.
// ---------------------------------------------------------------------------

async function linuxGet(): Promise<Buffer | null> {
  const r = await run("secret-tool", ["lookup", "service", SERVICE, "account", ACCOUNT]);
  if (r.code !== 0) return null;
  const value = r.stdout.replace(/\n$/, "");
  if (value.length === 0) return null;
  return decodeKey(value);
}

async function linuxStore(keyB64: string): Promise<boolean> {
  const r = await run(
    "secret-tool",
    ["store", "--label=mcpm secret store master key", "service", SERVICE, "account", ACCOUNT],
    { input: keyB64 }
  );
  return r.code === 0;
}

// ---------------------------------------------------------------------------
// Windows — DPAPI (CurrentUser scope) via PowerShell. The protected blob is
// stored in ~/.mcpm; DPAPI ties decryption to the Windows user account, so a
// copied blob cannot be unprotected by another account or on another machine.
// The plaintext key is passed through an env var, never argv (process list).
// ---------------------------------------------------------------------------

const PS_PROTECT =
  "$ErrorActionPreference='Stop';" +
  "Add-Type -AssemblyName System.Security;" +
  "$b=[Convert]::FromBase64String($env:MCPM_KEY_B64);" +
  "$p=[Security.Cryptography.ProtectedData]::Protect($b,$null,'CurrentUser');" +
  "[Convert]::ToBase64String($p)";

const PS_UNPROTECT =
  "$ErrorActionPreference='Stop';" +
  "Add-Type -AssemblyName System.Security;" +
  "$b=[Convert]::FromBase64String($env:MCPM_BLOB_B64);" +
  "$p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,'CurrentUser');" +
  "[Convert]::ToBase64String($p)";

async function blobPath(): Promise<string> {
  return path.join(await getStorePath(), DPAPI_BLOB_FILE);
}

async function windowsGet(): Promise<Buffer | null> {
  let blob: string;
  try {
    blob = (await readFile(await blobPath(), "utf8")).trim();
  } catch {
    return null; // no blob stored yet
  }
  if (blob.length === 0) return null;
  const r = await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", PS_UNPROTECT], {
    env: { ...process.env, MCPM_BLOB_B64: blob },
  });
  if (r.code !== 0) return null;
  return decodeKey(r.stdout.trim());
}

async function windowsStore(keyB64: string): Promise<boolean> {
  const r = await run("powershell", ["-NoProfile", "-NonInteractive", "-Command", PS_PROTECT], {
    env: { ...process.env, MCPM_KEY_B64: keyB64 },
  });
  if (r.code !== 0 || r.stdout.trim().length === 0) return false;
  try {
    await writeFile(await blobPath(), r.stdout.trim(), { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Shared helpers + public dispatch
// ---------------------------------------------------------------------------

/** Decode a base64 master key, rejecting anything that is not exactly 32 bytes. */
function decodeKey(b64: string): Buffer | null {
  try {
    const buf = Buffer.from(b64, "base64");
    return buf.length === 32 ? buf : null;
  } catch {
    return null;
  }
}

/**
 * Read the stored master key, or null if none is stored / the store is
 * unavailable. Never creates a key.
 */
export async function getStoredKey(): Promise<Buffer | null> {
  if (!isSupportedPlatform()) return null;
  switch (process.platform) {
    case "darwin":
      return darwinGet();
    case "linux":
      return linuxGet();
    case "win32":
      return windowsGet();
    default:
      return null;
  }
}

/**
 * Persist `key` (exactly 32 bytes) in the OS credential store. Returns true on
 * success, false if the store is unavailable or the write failed.
 */
export async function storeKey(key: Buffer): Promise<boolean> {
  if (!isSupportedPlatform()) return false;
  if (key.length !== 32) return false;
  const keyB64 = key.toString("base64");
  switch (process.platform) {
    case "darwin":
      return darwinStore(keyB64);
    case "linux":
      return linuxStore(keyB64);
    case "win32":
      return windowsStore(keyB64);
    default:
      return false;
  }
}
