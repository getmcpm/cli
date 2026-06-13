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
import { defaultActionForFinding, ACTION_RANK } from "./patterns.js";
import {
  PinsIntegrityError,
  hashToolDefinition,
  fieldHashesOf,
  readPins,
  upsertToolPin,
  writePins,
  type FieldHashes,
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
): ChangedField[] {
  if (pinned === undefined) return [];
  const changed: ChangedField[] = [];
  if (pinned.description !== live.description) changed.push("description");
  if (pinned.schema !== live.schema) changed.push("schema");
  if (pinned.annotations !== live.annotations) changed.push("annotations");
  return changed;
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
export function classifyDrift(pinned: PinEntry, liveFields: FieldHashes): DriftClass {
  if (pinned.field_hashes === undefined) {
    return { kind: "security", changedFields: [] };
  }
  const changed = diffToolDefinition(pinned.field_hashes, liveFields);
  if (changed.length === 1 && changed[0] === "description") {
    return { kind: "cosmetic", changedFields: changed };
  }
  return { kind: "security", changedFields: changed };
}

/** Strip control + ANSI escape sequences from tool/server names (security F9). */
function sanitizeLabel(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1B(?:[@-Z\\\-_]|\[[0-9;]*[a-zA-Z])/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1F\x7F\x80-\x9F]/g, "")
    .slice(0, 128);
}

/** Safe pin lookup using Object.hasOwn — defeats `__proto__` / `constructor` shenanigans (security F13). */
function lookupPin(pins: PinsFile, serverName: string, toolName: string): PinEntry | undefined {
  if (!Object.hasOwn(pins.servers, serverName)) return undefined;
  const server = pins.servers[serverName];
  if (server === undefined || !Object.hasOwn(server, toolName)) return undefined;
  return server[toolName];
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
}): InspectFinding {
  const { cls, safeServer, safeTool, expected, actual, newDescriptionExcerpt } = args;
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
        `If intended, run \`mcpm guard accept-drift ${safeServer} --tool ${safeTool} --new-hash ${actual}\` to silence it.`,
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
      `If this is a legitimate server upgrade, run \`mcpm guard accept-drift ${safeServer} --tool ${safeTool} --new-hash ${actual}\` ` +
      `(or \`--remove\` to drop the pin entirely).`,
  };
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
    if (err instanceof PinsIntegrityError) {
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

    if (existing.current_hash !== liveHash) {
      // Drift. Classify by field (cosmetic vs security). Do NOT auto-re-pin —
      // the durable baseline only moves via an explicit `accept-drift`.
      driftedTools.push({
        toolName,
        expected: existing.current_hash,
        actual: liveHash,
        cls: classifyDrift(existing, liveFields),
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
  const action = findings.reduce<InspectResult["action"]>((acc, f) => {
    const a = defaultActionForFinding(f);
    return ACTION_RANK[a] > ACTION_RANK[acc] ? a : acc;
  }, "pass");
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
  if (options.newHash === undefined || !/^sha256:[0-9a-f]{64}$/.test(options.newHash)) {
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

export async function acceptDriftCommand(
  serverName: string,
  options: { toolName?: string; remove?: boolean; newHash?: string } = {},
): Promise<void> {
  const pins = await readPins();
  const next = applyAcceptDrift(pins, serverName, options);
  if (next !== pins) await writePins(next);
}
