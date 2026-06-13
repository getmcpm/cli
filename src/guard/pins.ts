/**
 * Schema-pin storage for mcpm-guard (v0.5.0, Next Step 6).
 *
 * Persists per-server, per-tool SHA-256 hashes of the tool definition
 * (description + schema + annotations) captured at install time. Drift
 * detection at runtime compares the live tools/list response against
 * the pin and blocks if the hash has changed — catching rug-pull attacks
 * structurally, complementing the regex-based pattern engine.
 *
 * Storage:
 *   ~/.mcpm/pins.json            — pin data, JSON, format_version-tagged
 *   ~/.mcpm/pins.json.integrity  — SHA-256 of pins.json contents (sidecar)
 *
 * The integrity sidecar (security review F4.2) is an UNKEYED SHA-256 of
 * pins.json stored next to it with the same 0o600 perms. It provides
 * INTEGRITY (tamper-EVIDENCE against accidental corruption / cross-machine
 * copies / a different OS-user account), NOT AUTHENTICITY against a
 * same-user/postinstall attacker: any process that can write pins.json can
 * also recompute and rewrite this sidecar to match, so there is no
 * attacker/writer asymmetry. A keyed scheme (HMAC/signature) would need a
 * secret the writable store lacks — same constraint as the secret store
 * (security issue #15); deferred to OS-keychain support. See security issue
 * #19. Any mismatch on read refuses to use the pin file until the user runs
 * `mcpm guard reset-integrity`.
 *
 * Two-target scope: install-time capture writes captured_via:"install".
 * If install-time spawn fails (OAuth, network), a placeholder entry with
 * current_hash:null + captured_via:"first-session" is written; the next
 * successful runtime tools/list fills the hash.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, rename, unlink, lstat } from "node:fs/promises";
import path from "node:path";
import lockfile from "proper-lockfile";
import { z } from "zod";
import { getStorePath } from "../store/index.js";

const PINS_FILENAME = "pins.json";
const INTEGRITY_FILENAME = "pins.json.integrity";

export const PINS_FORMAT_VERSION = 1;

export type CapturedVia = "install" | "first-session" | "backfill";

/**
 * H4: per-field SHA-256 hashes of the SAME canonical leaves that feed
 * {@link hashToolDefinition}. Lets drift detection classify a whole-hash change
 * by WHICH field moved (description-only is cosmetic; schema/annotations is a
 * security-relevant capability change).
 */
export interface FieldHashes {
  description: string;
  schema: string;
  annotations: string;
}

export interface PinEntry {
  /** SHA-256 of JSON.stringify({description, schema, annotations}). null in first-session mode awaiting first session. */
  current_hash: string | null;
  /** Previous hashes kept for accept-drift history. */
  previous_hashes: string[];
  /** ISO 8601 timestamp. */
  captured_at: string;
  captured_via: CapturedVia;
  signature_list_version: string;
  /**
   * H4: per-field hashes (description / schema / annotations). OPTIONAL and
   * backward-compatible — pins captured before H4 lack this and fall back to
   * coarse whole-hash drift (treated conservatively as a security block). No
   * format_version bump: absence is a valid, known state.
   */
  field_hashes?: FieldHashes;
}

/**
 * H5: per-dimension SHA-256 hashes of the `initialize` handshake leaves we pin —
 * the declared `capabilities` object and `serverInfo.name`. Lets handshake-drift
 * detection tell a capability change from an identity change. NOTE: `instructions`
 * (free prose; already content-scanned by H1) and `serverInfo.version` (churns
 * every benign release) are DELIBERATELY excluded.
 */
export interface HandshakeFieldHashes {
  capabilities: string;
  serverName: string;
}

/**
 * H5: TOFU baseline of an MCP server's `initialize` handshake. Warn-tier only —
 * handshake drift NEVER blocks (blocking an initialize result kills the whole
 * session). Mirrors {@link PinEntry} but for the per-server handshake.
 */
export interface HandshakePinEntry {
  /** {@link hashHandshake} of the first-observed handshake field hashes. */
  current_hash: string;
  /** Whole-hashes already SURFACED to the user (warn-once cross-session dedup). */
  previous_hashes: string[];
  captured_at: string;
  /** "first-session" (TOFU). H3 install-pin capture is deferred. */
  captured_via: CapturedVia;
  signature_list_version: string;
  /** Per-dimension hashes — to tell capability-change from identity-change. */
  field_hashes: HandshakeFieldHashes;
  /** Sorted top-level keys of result.capabilities — for ADD vs REMOVE diffing. */
  capability_keys: string[];
}

export interface PinsFile {
  format_version: number;
  servers: Record<string, Record<string, PinEntry>>;
  /**
   * H5: per-server initialize-handshake pins. ADDITIVE + optional (no
   * format_version bump, mirrors H4's field_hashes): absence is a valid pre-H5
   * state; a present-but-malformed value fails the schema → readPins fails closed.
   */
  handshakes?: Record<string, HandshakePinEntry>;
}

// The integrity sidecar proves the BYTES are unchanged; it says nothing about
// the SHAPE. A structurally-malformed (but sidecar-consistent) pins.json — e.g.
// `servers` is an array, or an entry is missing `current_hash` — would slip
// through a bare `as PinsFile` cast and corrupt drift detection downstream.
// Validate the shape with Zod (mirrors policy.ts's GuardPolicyFileSchema) and
// throw a descriptive (NON-PinsIntegrityError) error so the user knows the file
// is structurally invalid, not tampered.
const FieldHashesSchema = z.object({
  description: z.string(),
  schema: z.string(),
  annotations: z.string(),
});
const PinEntrySchema = z.object({
  current_hash: z.string().nullable(),
  previous_hashes: z.array(z.string()),
  captured_at: z.string(),
  captured_via: z.enum(["install", "first-session", "backfill"]),
  signature_list_version: z.string(),
  // H4: optional + last field. A present-but-malformed value (non-object,
  // missing string fields) fails the schema → readPins rejects (fail closed).
  field_hashes: FieldHashesSchema.optional(),
});
// H5: handshake-pin schema, mirrors PinEntrySchema. A present-but-malformed
// `handshakes` value (missing fields, non-object field_hashes) fails the schema
// → readPins rejects (fail closed). Absence parses fine for pre-H5 files.
const HandshakeFieldHashesSchema = z.object({
  capabilities: z.string(),
  serverName: z.string(),
});
const HandshakePinEntrySchema = z.object({
  current_hash: z.string(),
  previous_hashes: z.array(z.string()),
  captured_at: z.string(),
  captured_via: z.enum(["install", "first-session", "backfill"]),
  signature_list_version: z.string(),
  field_hashes: HandshakeFieldHashesSchema,
  capability_keys: z.array(z.string()),
});
const PinsFileSchema = z.object({
  format_version: z.number(),
  servers: z.record(z.string(), z.record(z.string(), PinEntrySchema)),
  // H5: optional + additive. Same backward-compat discipline as field_hashes.
  handshakes: z.record(z.string(), HandshakePinEntrySchema).optional(),
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/**
 * Stable hash of a tool definition. Stringifies in canonical (sorted-key)
 * form so equivalent JSON with different key order produces the same hash.
 */
export function hashToolDefinition(input: {
  description?: string | null;
  schema?: unknown;
  annotations?: unknown;
}): string {
  const canonical = JSON.stringify(
    {
      description: input.description ?? "",
      schema: input.schema ?? null,
      annotations: input.annotations ?? null,
    },
    sortedReplacer,
  );
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * H4: hash EACH tool-definition field separately, using the SAME canonical
 * (sorted-key) form + leaf defaults as {@link hashToolDefinition}. The whole-hash
 * and these field hashes derive from identical canonical leaves, so a whole-hash
 * change implies (and is implied by) at least one field-hash change.
 */
export function fieldHashesOf(input: {
  description?: string | null;
  schema?: unknown;
  annotations?: unknown;
}): FieldHashes {
  return {
    description: hashLeaf(input.description ?? ""),
    schema: hashLeaf(input.schema ?? null),
    annotations: hashLeaf(input.annotations ?? null),
  };
}

function hashLeaf(value: unknown): string {
  const canonical = JSON.stringify(value, sortedReplacer);
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

/**
 * H5: per-dimension hashes of the pinned `initialize` handshake leaves. Reuses
 * {@link hashLeaf} (same canonical sorted form). DELIBERATELY excludes
 * `instructions` and `serverInfo.version`: a non-string name collapses to "" and
 * a missing `capabilities` collapses to null, so a version-only bump (or a name
 * that is absent vs. an empty string) produces identical field hashes.
 */
export function handshakeFieldHashesOf(result: {
  capabilities?: unknown;
  serverInfo?: { name?: unknown };
}): HandshakeFieldHashes {
  return {
    capabilities: hashLeaf(result.capabilities ?? null),
    serverName: hashLeaf(typeof result.serverInfo?.name === "string" ? result.serverInfo.name : ""),
  };
}

/**
 * H5: sorted top-level capability keys (e.g. ["resources","sampling","tools"]).
 * Empty list when `capabilities` is missing or not a plain object.
 */
export function handshakeCapabilityKeys(result: { capabilities?: unknown }): string[] {
  const caps = result.capabilities;
  if (caps === null || typeof caps !== "object" || Array.isArray(caps)) return [];
  return Object.keys(caps as Record<string, unknown>).sort();
}

/** H5: stable whole-hash of the handshake field hashes (the durable baseline value). */
export function hashHandshake(f: HandshakeFieldHashes): string {
  return hashLeaf({ capabilities: f.capabilities, serverName: f.serverName });
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
    return sorted;
  }
  return value;
}

export function emptyPinsFile(): PinsFile {
  return { format_version: PINS_FORMAT_VERSION, servers: {} };
}

// ---------------------------------------------------------------------------
// Read / write with integrity sidecar
// ---------------------------------------------------------------------------

export class PinsIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PinsIntegrityError";
  }
}

// Issue #19: UNKEYED SHA-256. This is an integrity checksum (tamper-evidence),
// not a keyed MAC — it cannot authenticate the writer. A same-user/postinstall
// process can recompute this to match a malicious edit. Do not document it as
// anti-malware. A keyed scheme needs a secret the writable store lacks (#15).
function fileSha(content: string): string {
  return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`;
}

// #26 (replicated from config/adapters/base.ts, which does not export it): throw
// if `targetPath` is a symlink. lstat does not follow the final component, so
// this detects a symlinked target before a write follows it onto an
// attacker-chosen path. A missing path (ENOENT) is fine — nothing to traverse.
async function assertNotSymlink(targetPath: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>;
  try {
    st = await lstat(targetPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing to write pins through a symlink: ${targetPath}`);
  }
}

// Write `data` atomically to `target`: refuse symlinks, clear any stale `.tmp`
// (which may itself be a pre-placed symlink — unlinking removes only the link),
// then create the `.tmp` EXCLUSIVELY (wx) so it is a fresh, unfollowed inode,
// and rename into place. Mirrors base.ts/writeAtomic.
async function writeFileAtomic(target: string, data: string): Promise<void> {
  await assertNotSymlink(target);
  const tmp = `${target}.tmp`;
  try {
    await unlink(tmp);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  await writeFile(tmp, data, { encoding: "utf-8", mode: 0o600, flag: "wx" });
  await rename(tmp, target);
}

async function pinsPath(): Promise<string> {
  return path.join(await getStorePath(), PINS_FILENAME);
}

async function integrityPath(): Promise<string> {
  return path.join(await getStorePath(), INTEGRITY_FILENAME);
}

/**
 * Read the pin file + verify its integrity sidecar. Returns an empty pins
 * file if pins.json does not exist (first-run). Throws PinsIntegrityError
 * if the sidecar exists but does not match the file content — the user must
 * run `mcpm guard reset-integrity` before pins are usable again.
 */
export async function readPins(): Promise<PinsFile> {
  const filePath = await pinsPath();
  const sidecarPath = await integrityPath();

  let content: string;
  try {
    content = await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return emptyPinsFile();
    throw err;
  }

  // If the sidecar exists, it must match. If the sidecar is missing, treat as
  // first-run — write a fresh sidecar on the next writePins.
  let sidecar: string | null = null;
  try {
    sidecar = (await readFile(sidecarPath, "utf-8")).trim();
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  if (sidecar !== null) {
    const actual = fileSha(content);
    if (actual !== sidecar) {
      throw new PinsIntegrityError(
        `pins.json integrity check failed (expected ${sidecar}, got ${actual}). ` +
          `If you intentionally modified ~/.mcpm/pins.json (e.g., copied between machines), ` +
          `run \`mcpm guard reset-integrity\`. Otherwise, review ~/.mcpm/guard-events.jsonl ` +
          `for unauthorized activity.`,
      );
    }
  }

  // The sidecar guarantees byte integrity; Zod guarantees the SHAPE. Anything
  // that parses as JSON but is not a well-formed PinsFile (e.g. a hand-edit, a
  // truncated write, an incompatible future schema) is rejected with a clear,
  // NON-PinsIntegrityError message so the user knows it is structurally invalid
  // rather than tampered.
  let json: unknown;
  try {
    json = JSON.parse(content);
  } catch (err) {
    throw new Error(
      `pins.json is not valid JSON (${(err as Error).message}). The file at ` +
        `~/.mcpm/pins.json is corrupt; remove it to start fresh or restore from a backup.`,
    );
  }
  const result = PinsFileSchema.safeParse(json);
  if (!result.success) {
    throw new Error(
      `pins.json has an invalid structure: ${result.error.issues
        .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
        .join("; ")}. The file is structurally invalid (not tampered); ` +
        `remove ~/.mcpm/pins.json to start fresh or restore from a backup.`,
    );
  }
  const parsed = result.data as PinsFile;
  if (parsed.format_version !== PINS_FORMAT_VERSION) {
    throw new Error(
      `pins.json format_version mismatch (file: ${parsed.format_version}, expected: ${PINS_FORMAT_VERSION}). ` +
        `Migration is not yet implemented — file an issue.`,
    );
  }
  return parsed;
}

/**
 * Write pins.json + refresh the integrity sidecar. Atomic via .tmp + rename.
 *
 * Uses proper-lockfile (security review F2) to serialize concurrent writes
 * from multiple IDE sessions hitting the same wrapped server. Without the
 * lock, two relays writing first-session pins can race and corrupt the
 * sidecar relative to pins.json.
 */
export async function writePins(pins: PinsFile): Promise<void> {
  const filePath = await pinsPath();
  const sidecarPath = await integrityPath();
  const serialized = `${JSON.stringify(pins, null, 2)}\n`;

  // Touch the file first if it doesn't exist — proper-lockfile requires
  // the target to exist before locking.
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
    await writeFileAtomic(filePath, serialized);
    await writeFileAtomic(sidecarPath, fileSha(serialized));
  } finally {
    await release();
  }
}

/**
 * Force-regenerate the integrity sidecar from whatever pins.json currently
 * contains. Used by `mcpm guard reset-integrity` after the user has reviewed
 * the file and acknowledged the tamper warning.
 */
export async function resetIntegrity(): Promise<void> {
  const filePath = await pinsPath();
  const sidecarPath = await integrityPath();
  let content: string;
  try {
    content = await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // Nothing to reset; remove any stale sidecar.
      await unlink(sidecarPath).catch(() => undefined);
      return;
    }
    throw err;
  }
  // Route the sidecar write through the same hardened atomic writer used by
  // writePins (assertNotSymlink + stale-.tmp unlink + {flag:"wx"}). A bare
  // writeFile(`${sidecarPath}.tmp`) + rename would follow a pre-placed symlink
  // at the sidecar (or its .tmp), redirecting the write onto an attacker-chosen
  // path — the exact gap the PR closed for the main pins/policy writes.
  await writeFileAtomic(sidecarPath, fileSha(content));
}

// ---------------------------------------------------------------------------
// Mutation helpers — pure functions that return new PinsFile instances
// ---------------------------------------------------------------------------

export function upsertToolPin(
  pins: PinsFile,
  serverName: string,
  toolName: string,
  newEntry: PinEntry,
): PinsFile {
  const server = pins.servers[serverName] ?? {};
  return {
    ...pins,
    servers: {
      ...pins.servers,
      [serverName]: { ...server, [toolName]: newEntry },
    },
  };
}

/**
 * H5: immutably set a server's handshake pin. Parity with {@link upsertToolPin}.
 * Spreads `pins.handshakes ?? {}` so a pre-H5 file (no `handshakes` key) is
 * upgraded in place without mutating the input.
 */
export function upsertHandshakePin(
  pins: PinsFile,
  serverName: string,
  entry: HandshakePinEntry,
): PinsFile {
  return {
    ...pins,
    handshakes: { ...(pins.handshakes ?? {}), [serverName]: entry },
  };
}

/**
 * H5: safe handshake lookup via Object.hasOwn (F13) — defeats `__proto__` /
 * `constructor` confusion and never resolves an inherited prototype member.
 */
export function lookupHandshake(pins: PinsFile, serverName: string): HandshakePinEntry | undefined {
  const handshakes = pins.handshakes ?? {};
  if (!Object.hasOwn(handshakes, serverName)) return undefined;
  return handshakes[serverName];
}

export function clearServerPins(pins: PinsFile, serverName: string): PinsFile {
  if (!pins.servers[serverName]) return pins;
  const { [serverName]: _removed, ...rest } = pins.servers;
  return { ...pins, servers: rest };
}

export function clearToolPin(
  pins: PinsFile,
  serverName: string,
  toolName: string,
): PinsFile {
  const server = pins.servers[serverName];
  if (!server || !server[toolName]) return pins;
  const { [toolName]: _removed, ...rest } = server;
  return {
    ...pins,
    servers: { ...pins.servers, [serverName]: rest },
  };
}

/**
 * Move the current hash into previous_hashes + set a new current.
 * Used when a drift is "accepted" — preserves history without losing
 * the audit trail of prior hashes.
 */
export function acceptDrift(
  pins: PinsFile,
  serverName: string,
  toolName: string,
  newHash: string,
): PinsFile {
  const existing = pins.servers[serverName]?.[toolName];
  if (!existing) return pins;
  // H4: drop the stale field_hashes (they describe the OLD definition; keeping
  // them past a current_hash rewrite breaks the whole⟺field invariant and can
  // mis-tier a later drift toward less-safe). The entry reverts to coarse
  // SECURITY tiering until a fresh first-session capture re-derives them.
  const { field_hashes: _staleFieldHashes, ...rest } = existing;
  const updated: PinEntry = {
    ...rest,
    current_hash: newHash,
    previous_hashes: existing.current_hash
      ? [...existing.previous_hashes, existing.current_hash]
      : existing.previous_hashes,
    captured_at: new Date().toISOString(),
  };
  return upsertToolPin(pins, serverName, toolName, updated);
}
