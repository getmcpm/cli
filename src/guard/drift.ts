/**
 * Schema-drift detection (v0.5.0, Next Step 6).
 *
 * Wired into the relay's `inspectChildResponse` callback. When a `tools/list`
 * response arrives, hash each tool definition and compare against the pin.
 *
 *   - hash matches pin       → pass
 *   - hash differs from pin  → BLOCK (rug-pull) until accept-drift
 *   - pin missing entirely   → first-session capture (write the new pin,
 *                              return pass — the user is opting in by
 *                              running the server for the first time)
 *
 * This is a separate inspection from the pattern engine (patterns.ts) which
 * scans for injection text. Schema drift catches a different attack class
 * (server rewrites tool definitions after the user approved them at install).
 */

import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import type { InspectFinding, InspectResult } from "./types.js";
import { worstAction } from "./patterns.js";
import { sanitizeForTerminal } from "./sanitize.js";
import { canonicalToolName } from "./key-canon.js";
import {
  PinsIntegrityError,
  HASH_REGEX,
  hashToolDefinition,
  pinStillMatches,
  legacyFieldHashCandidates,
  legacyHandshakeFieldCandidates,
  handshakeStillMatches,
  fieldHashesOf,
  handshakeFieldHashesOf,
  handshakeCapabilityKeys,
  hashHandshake,
  lookupHandshake,
  upsertHandshakePin,
  readPins,
  upsertToolPin,
  writePins,
  type FieldHashes,
  type HandshakeFieldHashes,
  type HandshakePinEntry,
  type PinEntry,
  type PinsFile,
} from "./pins.js";

// ---------------------------------------------------------------------------
// H4: field-level drift classification
// ---------------------------------------------------------------------------

export type ChangedField = "description" | "schema" | "annotations";

export interface DriftClass {
  readonly kind: "none" | "cosmetic" | "security";
  readonly changedFields: ChangedField[];
}

/**
 * Compare the three tool-definition fields by EXPLICIT NAMED access (never
 * dynamic bracket-indexing of attacker-influenced keys). Returns the changed
 * fields in fixed order. If `pinned` is undefined (a pre-H4 pin) returns `[]` —
 * the caller treats absence as a coarse (whole-hash) comparison.
 */
export function diffToolDefinition(
  pinned: FieldHashes | undefined,
  live: FieldHashes,
  /**
   * #26: alternative spellings of the LIVE field hashes, for a pin written
   * before NFC folding. A field whose stored hash matches any of them is
   * canonically equivalent to the live text, i.e. unchanged.
   */
  alternates: readonly FieldHashes[] = [],
): ChangedField[] {
  if (pinned === undefined) return [];
  const changed: ChangedField[] = [];
  if (pinned.description !== live.description && !alternates.some((a) => a.description === pinned.description))
    changed.push("description");
  if (pinned.schema !== live.schema && !alternates.some((a) => a.schema === pinned.schema)) changed.push("schema");
  if (pinned.annotations !== live.annotations && !alternates.some((a) => a.annotations === pinned.annotations))
    changed.push("annotations");
  return changed;
}

/**
 * The H4 tiering RULE itself, shared by {@link classifyDrift} (against a
 * durable disk pin) and {@link classifyFieldDrift} (#58, against a
 * session-only baseline): description-only change → cosmetic; anything
 * touching schema and/or annotations (or a coarse no-baseline comparison) →
 * security.
 */
function tierChangedFields(changed: ChangedField[]): DriftClass {
  if (changed.length === 1 && changed[0] === "description") {
    return { kind: "cosmetic", changedFields: changed };
  }
  return { kind: "security", changedFields: changed };
}

/**
 * Classify a drift (PRECONDITION, caller-enforced: pinned.current_hash !== null
 * and the live whole-hash already differs from it).
 *
 *  - pre-H4 pin (no field_hashes)        → coarse SECURITY block (never less safe
 *                                           than today; old pins stay strict).
 *  - description-only change             → COSMETIC (warn, non-blocking wording).
 *  - schema and/or annotations (or any   → SECURITY (block: a capability change).
 *    multi-field change)
 */
export function classifyDrift(
  pinned: PinEntry,
  liveFields: FieldHashes,
  /** #26: see {@link diffToolDefinition}. Omit for a same-build baseline. */
  liveFieldAlternates: readonly FieldHashes[] = [],
): DriftClass {
  if (pinned.field_hashes === undefined) {
    return { kind: "security", changedFields: [] };
  }
  return tierChangedFields(diffToolDefinition(pinned.field_hashes, liveFields, liveFieldAlternates));
}

/**
 * #58 (Deadbugz): the SAME H4 tiering rule as {@link classifyDrift}, but
 * against a SESSION-observed field-hash baseline instead of a durable disk
 * pin. Used by the armed same-session `list_changed` re-validation path
 * (run-inner.ts) — its baseline is "what this tool looked like the first
 * time this session saw it", which exists even for a server that has never
 * been guarded before (no pin on disk yet to classify against).
 */
export function classifyFieldDrift(baseline: FieldHashes, liveFields: FieldHashes): DriftClass {
  return tierChangedFields(diffToolDefinition(baseline, liveFields));
}

/** Strip control + ANSI escape sequences from tool/server names (security F9). */
function sanitizeLabel(s: string): string {
  return sanitizeForTerminal(s, 128);
}

/**
 * Safe pin lookup using Object.hasOwn — defeats `__proto__` / `constructor`
 * shenanigans (security F13) — resolving a CONFUSABLE tool name onto the pin it
 * impersonates (TODOS #58 residual).
 *
 * Exact raw key first: that is the identity path for every conforming name, so
 * an existing pins.json keeps resolving byte-for-byte and no migration or
 * PINS_FORMAT_VERSION bump is needed. Only if there is no exact hit do we fall
 * back to the canonical form, so a `Format_Code` / `fоrmat_code` (Cyrillic о) /
 * zero-width twin is compared against the `format_code` pin it is imitating
 * instead of being filed as a brand-new tool.
 *
 * An AMBIGUOUS canonical match (two stored keys folding to the same form) is
 * left UNRESOLVED rather than guessing which pin the caller meant — guessing
 * could compare a tool against a sibling's baseline and manufacture drift.
 * Writes still use the raw name (see upsertToolPin), so the store stays
 * human-readable and byte-compatible with every earlier release.
 */
/**
 * Safe pin lookup using Object.hasOwn — defeats `__proto__` / `constructor`
 * shenanigans (security F13) — resolving a CONFUSABLE tool name onto the pin it
 * impersonates (TODOS #58 residual).
 *
 * Exact raw key FIRST: the identity path for every conforming name, so an
 * existing pins.json keeps resolving byte-for-byte — no migration, no
 * PINS_FORMAT_VERSION bump. Only with no exact hit do we fall back to the
 * canonical form, so a `Format_Code` / Cyrillic `fоrmat_code` / zero-width twin
 * is compared against the pin it is imitating instead of being filed as a new
 * tool. Writes still use the raw name (upsertToolPin), so the store stays
 * human-readable and byte-compatible with every earlier release.
 *
 * `ambiguous` (two stored keys folding together, and no exact hit) is reported
 * rather than silently resolved OR silently ignored. Guessing could compare a
 * tool against a sibling's baseline and manufacture drift; returning "not
 * pinned" would fail OPEN — an adversarial review found that a server can plant
 * two canonically-colliding names in its first-ever list, after which every
 * confusable spelling of that tool would permanently read as a brand-new tool.
 * The caller turns this state into a finding.
 */
export type ToolPinLookup =
  | { readonly kind: "exact"; readonly key: string; readonly entry: PinEntry }
  | { readonly kind: "canonical"; readonly key: string; readonly entry: PinEntry }
  | { readonly kind: "ambiguous" }
  | { readonly kind: "none" };

/**
 * canonical name -> the stored raw keys that fold to it, built ONCE per pins
 * object. Without this the fallback re-canonicalizes every stored key on every
 * exact-miss: measured 4.3 s of synchronous relay time for a server with 3000
 * pinned tools whose names all changed, against a p99 budget of 3.1 ms. Keyed
 * on the frozen PinsFile sub-object's identity, so a re-read (which builds new
 * objects) rebuilds naturally and a stale index cannot outlive its store.
 */
const canonIndexCache = new WeakMap<object, Map<string, string[]>>();

function canonIndex(server: Record<string, PinEntry>): Map<string, string[]> {
  const hit = canonIndexCache.get(server);
  if (hit !== undefined) return hit;
  const index = new Map<string, string[]>();
  for (const key of Object.keys(server)) {
    const canon = canonicalToolName(key);
    const bucket = index.get(canon);
    if (bucket === undefined) index.set(canon, [key]);
    else bucket.push(key);
  }
  canonIndexCache.set(server, index);
  return index;
}

export function lookupToolPin(
  server: Record<string, PinEntry> | undefined,
  toolName: string,
  opts?: { readonly exactOnly?: boolean },
): ToolPinLookup {
  if (server === undefined) return { kind: "none" };
  if (Object.hasOwn(server, toolName)) {
    const entry = server[toolName];
    if (entry !== undefined) return { kind: "exact", key: toolName, entry };
  }
  if (opts?.exactOnly === true) return { kind: "none" };
  const keys = canonIndex(server).get(canonicalToolName(toolName));
  if (keys === undefined) return { kind: "none" };
  let found: { key: string; entry: PinEntry } | undefined;
  for (const key of keys) {
    const entry = server[key];
    if (entry === undefined) continue;
    if (found !== undefined) return { kind: "ambiguous" };
    found = { key, entry };
  }
  return found === undefined ? { kind: "none" } : { kind: "canonical", ...found };
}

function lookupPin(pins: PinsFile, serverName: string, toolName: string): PinEntry | undefined {
  if (!Object.hasOwn(pins.servers, serverName)) return undefined;
  const r = lookupToolPin(pins.servers[serverName], toolName);
  return r.kind === "exact" || r.kind === "canonical" ? r.entry : undefined;
}

/**
 * H4: build the tiered drift finding for a drifted tool, shared by the async
 * {@link inspectForDrift} and the sync run-inner path so both agree.
 *
 *  - cosmetic → `schema-drift-cosmetic`, severity high (→ warn). Non-blocking
 *    wording change; still requires `accept-drift` to silence. NOT auto-re-pinned.
 *  - security/coarse → `schema-drift`, severity critical (→ block). Carries which
 *    fields changed + the accept-drift / --new-hash remediation.
 *
 * `cls.changedFields` is a fixed-vocabulary enum list (never attacker keys), so
 * naming it in the excerpt is safe. `safeServer` / `safeTool` are pre-sanitized.
 */
export function buildDriftFinding(args: {
  cls: DriftClass;
  safeServer: string;
  safeTool: string;
  expected: string;
  actual: string;
  /**
   * H4 structured audit: the NEW description, already sanitized + truncated by
   * the caller (the pin only stores hashes, so the OLD description is not
   * recoverable here — we surface the new wording so the guard-events.jsonl
   * entry is self-contained for review). Optional: the off-thread drift.ts path
   * does not pass it.
   */
  newDescriptionExcerpt?: string;
  /**
   * The key this tool's pin is actually STORED under, when the live name only
   * resolved to it canonically (a look-alike spelling). `accept-drift --tool`
   * looks the key up exactly, so the remediation must name the stored key or it
   * hands the user a command that silently does nothing (review).
   */
  pinnedAs?: string;
}): InspectFinding {
  const { cls, safeServer, safeTool, expected, actual, newDescriptionExcerpt } = args;
  const target = args.pinnedAs ?? safeTool;
  const alias =
    args.pinnedAs !== undefined && args.pinnedAs !== safeTool
      ? ` This name is a look-alike of the pinned tool "${args.pinnedAs}", which is the name to pass to \`--tool\`.`
      : "";
  if (cls.kind === "cosmetic") {
    const fields = cls.changedFields.join(",");
    const newExcerpt = newDescriptionExcerpt ? ` new="${newDescriptionExcerpt}"` : "";
    return {
      signature_id: "schema-drift-cosmetic",
      category: "OWASP-MCP-1",
      severity: "high",
      target: "tool_description",
      matched_text_excerpt: `${safeTool}: ${fields} changed (cosmetic)${newExcerpt}`,
      remediation:
        `Tool "${safeTool}" ${fields} wording changed since install — a non-blocking ` +
        `change (schema + annotations unchanged).${newExcerpt ? ` New wording:${newExcerpt}.` : ""} ` +
        `If intended, run \`mcpm guard accept-drift ${safeServer} --tool ${target} --new-hash ${actual}\` to silence it.${alias}`,
    };
  }
  const fields = cls.changedFields.length > 0 ? cls.changedFields.join(",") : "definition";
  return {
    signature_id: "schema-drift",
    category: "OWASP-MCP-1",
    severity: "critical",
    target: "tool_description",
    matched_text_excerpt: `${safeTool}: ${fields} changed (${expected.slice(7, 19)}… → ${actual.slice(7, 19)}…)`,
    remediation:
      `Tool "${safeTool}" schema changed since install (rug-pull suspected). ` +
      `If this is a legitimate server upgrade, run \`mcpm guard accept-drift ${safeServer} --tool ${target} --new-hash ${actual}\` ` +
      `(or \`--remove\` to drop the pin entirely).${alias}`,
  };
}

// ---------------------------------------------------------------------------
// H5: initialize-handshake drift classification (capabilities + identity)
// ---------------------------------------------------------------------------

export interface HandshakeDriftClass {
  readonly kind: "none" | "capability" | "identity" | "both";
  /** Capability keys present LIVE but not in the pin (set semantics). */
  readonly addedCaps: string[];
  /** Capability keys present in the pin but not LIVE. */
  readonly removedCaps: string[];
  readonly identityChanged: boolean;
}

/**
 * Classify a handshake drift by EXPLICIT named field (never bracket attacker
 * keys). PRECONDITION (caller-enforced): the live whole-hash already differs from
 * pinned.current_hash, so at least one dimension moved.
 *
 *  - capabilities-hash differs → capability dimension (addedCaps = live \ pinned,
 *    removedCaps = pinned \ live).
 *  - serverName-hash differs   → identity dimension.
 */
export function classifyHandshakeDrift(
  pinned: HandshakePinEntry,
  liveFields: HandshakeFieldHashes,
  liveCapKeys: string[],
  /** #26: alternative spellings of the LIVE dimension hashes, for a pre-NFC pin. */
  liveFieldAlternates: readonly HandshakeFieldHashes[] = [],
): HandshakeDriftClass {
  const capabilityChanged =
    pinned.field_hashes.capabilities !== liveFields.capabilities &&
    !liveFieldAlternates.some((a) => a.capabilities === pinned.field_hashes.capabilities);
  const identityChanged =
    pinned.field_hashes.serverName !== liveFields.serverName &&
    !liveFieldAlternates.some((a) => a.serverName === pinned.field_hashes.serverName);

  const pinnedKeys = new Set(pinned.capability_keys);
  const liveKeys = new Set(liveCapKeys);
  const addedCaps = capabilityChanged ? liveCapKeys.filter((k) => !pinnedKeys.has(k)) : [];
  const removedCaps = capabilityChanged ? pinned.capability_keys.filter((k) => !liveKeys.has(k)) : [];

  let kind: HandshakeDriftClass["kind"] = "none";
  if (capabilityChanged && identityChanged) kind = "both";
  else if (capabilityChanged) kind = "capability";
  else if (identityChanged) kind = "identity";

  return { kind, addedCaps, removedCaps, identityChanged };
}

// Capability grants that hand the server an active channel to the model/user —
// not just a passive surface change. Named in the warn copy as an escalation.
const ESCALATION_CAPS = new Set(["sampling", "elicitation"]);

/**
 * Build the warn-tier handshake-drift findings (one per changed dimension). ALL
 * findings are severity "high" → warn via severityToAction, so they NEVER block
 * (blocking an initialize result kills the session). Carried on the
 * `initialize_instructions` target (the handshake carrier); high is already warn,
 * so the carrier choice does not re-clamp it.
 *
 * Remediation copy says "since FIRST OBSERVED" (TOFU — there is no approval
 * moment until H3), never "since you approved". `safeServer` is pre-sanitized;
 * capability keys come from the live/pinned key lists (server-influenced) so they
 * are sanitized here before being named.
 */
export function buildHandshakeDriftFinding(args: {
  cls: HandshakeDriftClass;
  safeServer: string;
}): InspectFinding[] {
  const { cls, safeServer } = args;
  const findings: InspectFinding[] = [];

  if (cls.kind === "capability" || cls.kind === "both") {
    const added = cls.addedCaps.map(sanitizeLabel);
    const removed = cls.removedCaps.map(sanitizeLabel);
    const escalations = added.filter((k) => ESCALATION_CAPS.has(k));
    const addedStr = added.length > 0 ? `added [${added.join(", ")}]` : "";
    const removedStr = removed.length > 0 ? `removed [${removed.join(", ")}]` : "";
    const change = [addedStr, removedStr].filter(Boolean).join(", ") || "capabilities changed";
    const escalationNote =
      escalations.length > 0
        ? ` Granting [${escalations.join(", ")}] is a capability/grant escalation — the ` +
          `server can now drive sampling/elicitation prompts (their CONTENT is separately ` +
          `injection-scanned by the relay; this is the change-observability layer).`
        : "";
    findings.push({
      signature_id: "handshake-drift-capability",
      category: "OWASP-MCP-8",
      severity: "high",
      target: "initialize_instructions",
      matched_text_excerpt: `${safeServer}: capabilities ${change}`,
      remediation:
        `Server "${safeServer}" declares different capabilities (${change}) than first observed.` +
        escalationNote +
        ` If this is an intended upgrade, no action is needed — this warning auto-quiets once ` +
        `surfaced. If unexpected, inspect the wrapped command.`,
    });
  }

  if (cls.kind === "identity" || cls.kind === "both") {
    findings.push({
      signature_id: "handshake-drift-identity",
      category: "OWASP-MCP-1",
      severity: "high",
      target: "initialize_instructions",
      matched_text_excerpt: `${safeServer}: serverInfo.name changed since first observed`,
      remediation:
        `Server "${safeServer}" reports a different serverInfo.name than first observed — ` +
        `possible impersonation or the wrong binary wrapped. Verify the wrapped command. ` +
        `This warning auto-quiets once surfaced.`,
    });
  }

  return findings;
}

interface ToolDefinition {
  name?: unknown;
  description?: unknown;
  schema?: unknown;
  annotations?: unknown;
  /** Some servers use inputSchema vs schema — accept either. */
  inputSchema?: unknown;
}

function isToolDefinition(value: unknown): value is ToolDefinition {
  return value !== null && typeof value === "object";
}

function extractTools(msg: JSONRPCMessage): readonly ToolDefinition[] | null {
  if (!("result" in msg)) return null;
  const result = (msg as { result?: { tools?: unknown } }).result;
  const tools = result?.tools;
  if (!Array.isArray(tools)) return null;
  return tools.filter(isToolDefinition);
}

export interface DriftCheckDeps {
  readonly read: () => Promise<PinsFile>;
  readonly write: (pins: PinsFile) => Promise<void>;
  readonly signatureListVersion: string;
}

/**
 * Inspect a tools/list response against the pin store. May mutate the pin
 * store (first-session capture). Returns a relay InspectResult that the
 * caller combines with pattern-engine results before deciding to block.
 */
export async function inspectForDrift(
  msg: JSONRPCMessage,
  serverName: string,
  deps: DriftCheckDeps,
): Promise<InspectResult> {
  const tools = extractTools(msg);
  if (tools === null || tools.length === 0) {
    return { action: "pass", findings: [] };
  }

  let pins: PinsFile;
  try {
    pins = await deps.read();
  } catch (err) {
    // SECURITY F1: fail CLOSED on a known integrity violation. Failing open
    // would let a tampered pins.json (matched-back sidecar from a same-user
    // attacker) silently disable drift detection. Transient I/O errors fail
    // open since they're recoverable.
    if (err instanceof PinsIntegrityError) return pinsIntegrityBlock();
    return { action: "pass", findings: [] };
  }

  const driftedTools: {
    toolName: string;
    expected: string;
    actual: string;
    cls: DriftClass;
  }[] = [];
  let pinsAfter = pins;

  for (const tool of tools) {
    const toolName = typeof tool.name === "string" ? tool.name : null;
    if (toolName === null) continue;

    const fields = {
      description: typeof tool.description === "string" ? tool.description : null,
      schema: tool.inputSchema ?? tool.schema,
      annotations: tool.annotations,
    };
    const liveHash = hashToolDefinition(fields);
    const liveFields = fieldHashesOf(fields);

    const existing = lookupPin(pins, serverName, toolName);

    if (!existing) {
      // First-session capture. Write the pin (with H4 field hashes) and let
      // traffic through.
      const entry: PinEntry = {
        current_hash: liveHash,
        previous_hashes: [],
        captured_at: new Date().toISOString(),
        captured_via: "first-session",
        signature_list_version: deps.signatureListVersion,
        field_hashes: liveFields,
      };
      pinsAfter = upsertToolPin(pinsAfter, serverName, toolName, entry);
      continue;
    }

    if (existing.current_hash === null) {
      // Placeholder entry from a failed install-time capture. Fill it in now,
      // including H4 field hashes.
      const entry: PinEntry = {
        ...existing,
        current_hash: liveHash,
        captured_at: new Date().toISOString(),
        captured_via: "first-session",
        signature_list_version: deps.signatureListVersion,
        field_hashes: liveFields,
      };
      pinsAfter = upsertToolPin(pinsAfter, serverName, toolName, entry);
      continue;
    }

    if (!pinStillMatches(existing.current_hash, liveHash, fields)) {
      // Drift. Classify by field (cosmetic vs security). Do NOT auto-re-pin —
      // the durable baseline only moves via an explicit `accept-drift`.
      driftedTools.push({
        toolName,
        expected: existing.current_hash,
        actual: liveHash,
        cls: classifyDrift(existing, liveFields, legacyFieldHashCandidates(fields)),
      });
    }
  }

  // Best-effort persist any new / first-session-pin entries. Don't block on
  // write failures — drift detection is already as strict as it can be.
  if (pinsAfter !== pins) {
    await deps.write(pinsAfter).catch(() => undefined);
  }

  if (driftedTools.length === 0) {
    return { action: "pass", findings: [] };
  }

  const findings: InspectFinding[] = driftedTools.map((d) =>
    buildDriftFinding({
      cls: d.cls,
      safeServer: sanitizeLabel(serverName),
      safeTool: sanitizeLabel(d.toolName),
      expected: d.expected,
      actual: d.actual,
    }),
  );
  // Action = MAX over findings (cosmetic-only → warn; any security → block).
  const action = worstAction(findings);
  return { action, findings };
}

// ---------------------------------------------------------------------------
// H5: async initialize-handshake capture + cross-session warn-once dedup
// ---------------------------------------------------------------------------

export type HandshakeDriftDeps = DriftCheckDeps;

interface InitializeResult {
  capabilities?: unknown;
  serverInfo?: { name?: unknown };
}

function extractInitializeResult(msg: JSONRPCMessage): InitializeResult | null {
  if (!("result" in msg)) return null;
  const result = (msg as { result?: { protocolVersion?: unknown } }).result;
  if (result === null || typeof result !== "object") return null;
  if (typeof (result as { protocolVersion?: unknown }).protocolVersion !== "string") return null;
  return result as InitializeResult;
}

/** Shared fail-closed-on-integrity finding, reused by the tools/list + handshake arms. */
function pinsIntegrityBlock(): InspectResult {
  return {
    action: "block",
    findings: [
      {
        signature_id: "pins-integrity-failure",
        category: "OWASP-MCP-1",
        severity: "critical",
        target: "tool_description",
        matched_text_excerpt: "pins.json integrity check failed",
        remediation:
          "Schema-drift enforcement is offline. Review ~/.mcpm/pins.json " +
          "for unauthorized edits, then run `mcpm guard reset-integrity` to " +
          "re-acknowledge the file contents.",
      },
    ],
  };
}

/**
 * Async handshake inspection against the pin store. Mirrors {@link inspectForDrift}:
 *   - no pin   → first-session capture (write a `first-session` HandshakePinEntry,
 *                pass).
 *   - matches  → pass.
 *   - already-surfaced (live whole-hash ∈ previous_hashes) → pass (warn-once).
 *   - new drift → WARN findings; append the live whole-hash to previous_hashes so
 *                 the NEXT session's sync dedup skips it, WITHOUT moving
 *                 current_hash (NO auto-re-pin of the durable baseline).
 *
 * A PinsIntegrityError fails CLOSED (block); transient I/O fails open (pass).
 */
export async function inspectHandshakeForDrift(
  msg: JSONRPCMessage,
  serverName: string,
  deps: HandshakeDriftDeps,
): Promise<InspectResult> {
  const result = extractInitializeResult(msg);
  if (result === null) return { action: "pass", findings: [] };

  let pins: PinsFile;
  try {
    pins = await deps.read();
  } catch (err) {
    if (err instanceof PinsIntegrityError) return pinsIntegrityBlock();
    return { action: "pass", findings: [] };
  }

  const liveFields = handshakeFieldHashesOf(result);
  const liveCapKeys = handshakeCapabilityKeys(result);
  const liveWhole = hashHandshake(liveFields);

  const pinned = lookupHandshake(pins, serverName);

  // First-session capture (TOFU). Write the pin + pass.
  if (pinned === undefined) {
    const entry: HandshakePinEntry = {
      current_hash: liveWhole,
      previous_hashes: [],
      captured_at: new Date().toISOString(),
      captured_via: "first-session",
      signature_list_version: deps.signatureListVersion,
      field_hashes: liveFields,
      capability_keys: liveCapKeys,
    };
    await deps.write(upsertHandshakePin(pins, serverName, entry)).catch(() => undefined);
    return { action: "pass", findings: [] };
  }

  // Matches the durable baseline, or already surfaced once → no warn.
  if (
    handshakeStillMatches(pinned.current_hash, liveWhole, result) ||
    pinned.previous_hashes.some((h) => handshakeStillMatches(h, liveWhole, result))
  ) {
    return { action: "pass", findings: [] };
  }

  // New drift. Append the live whole-hash to previous_hashes (warn-once durable
  // dedup) WITHOUT moving current_hash — the baseline only moves via an explicit
  // re-pin (deferred to H3). Best-effort persist.
  const updated: HandshakePinEntry = {
    ...pinned,
    previous_hashes: [...pinned.previous_hashes, liveWhole],
  };
  await deps.write(upsertHandshakePin(pins, serverName, updated)).catch(() => undefined);

  const cls = classifyHandshakeDrift(pinned, liveFields, liveCapKeys, legacyHandshakeFieldCandidates(result));
  const findings = buildHandshakeDriftFinding({
    cls,
    safeServer: sanitizeLabel(serverName),
  });
  const action = worstAction(findings);
  return { action, findings };
}

/**
 * Apply an accept-drift decision. Re-reads the server's current schema by
 * letting the next session re-pin: clears the pin entry so the first
 * subsequent tools/list captures fresh. Returns the new PinsFile (caller
 * persists). Use when the user is OK with whatever schema arrives next.
 */
export function applyAcceptDrift(
  pins: PinsFile,
  serverName: string,
  options: { toolName?: string; remove?: boolean; newHash?: string },
): PinsFile {
  if (options.remove === true) {
    if (options.toolName !== undefined) {
      const server = pins.servers[serverName];
      if (!server) return pins;
      // Destructuring a MISSING key still builds a new object, so the caller's
      // `next !== pins` change-detection reported "removed" while removing
      // nothing — the false-success class v0.12.1's dogfood exists to catch,
      // and newly reachable now that a canonically-resolved block can name a
      // tool whose pin is stored under a different spelling (review).
      if (!Object.hasOwn(server, options.toolName)) return pins;
      const { [options.toolName]: _r, ...rest } = server;
      return { ...pins, servers: { ...pins.servers, [serverName]: rest } };
    }
    if (!pins.servers[serverName]) return pins;
    const { [serverName]: _r, ...rest } = pins.servers;
    return { ...pins, servers: rest };
  }

  // SECURITY F5: require an explicit --new-hash. Otherwise we'd set
  // current_hash to null which creates an unbounded "accept anything next"
  // window an attacker could race into. The user copies the hash from the
  // block-message remediation string.
  if (options.newHash === undefined || !HASH_REGEX.test(options.newHash)) {
    throw new Error(
      `accept-drift requires --new-hash <sha256:...> (or --remove to drop the pin). ` +
        `Copy the hash from the block message remediation field.`,
    );
  }

  const server = pins.servers[serverName];
  if (!server) return pins;

  const targets = options.toolName !== undefined ? [options.toolName] : Object.keys(server);
  let next = pins;
  for (const t of targets) {
    const existing = server[t];
    if (!existing) continue;
    // H4: drop the stale field_hashes. They describe the OLD definition, but
    // current_hash is being rewritten to the accepted one — keeping them would
    // break the whole-hash⟺field-hash invariant and let a LATER drift be
    // mis-tiered (cosmetic/warn) against fields that no longer match. Reverting
    // to no-field_hashes makes the entry classify as coarse SECURITY (block) on
    // the next change until a fresh first-session capture re-derives consistent
    // field hashes — fail-safe, matches the pre-H4-pin → coarse-security rule.
    const { field_hashes: _staleFieldHashes, ...rest } = existing;
    next = upsertToolPin(next, serverName, t, {
      ...rest,
      current_hash: options.newHash,
      previous_hashes: existing.current_hash
        ? [...existing.previous_hashes, existing.current_hash]
        : existing.previous_hashes,
      captured_at: new Date().toISOString(),
    });
  }
  return next;
}

/** Returns true if the pin set changed (a pin was re-pinned/removed), false if
 *  there was no matching existing pin so nothing was written. */
export async function acceptDriftCommand(
  serverName: string,
  options: { toolName?: string; remove?: boolean; newHash?: string } = {},
): Promise<boolean> {
  const pins = await readPins();
  const next = applyAcceptDrift(pins, serverName, options);
  const changed = next !== pins;
  if (changed) await writePins(next);
  return changed;
}
