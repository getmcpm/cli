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
import type { InspectResult } from "./types.js";
import {
  PinsIntegrityError,
  hashToolDefinition,
  readPins,
  upsertToolPin,
  writePins,
  type PinEntry,
  type PinsFile,
} from "./pins.js";

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

  const driftedTools: { toolName: string; expected: string; actual: string }[] = [];
  let pinsAfter = pins;

  for (const tool of tools) {
    const toolName = typeof tool.name === "string" ? tool.name : null;
    if (toolName === null) continue;

    const liveHash = hashToolDefinition({
      description: typeof tool.description === "string" ? tool.description : null,
      schema: tool.inputSchema ?? tool.schema,
      annotations: tool.annotations,
    });

    const existing = lookupPin(pins, serverName, toolName);

    if (!existing) {
      // First-session capture. Write the pin and let traffic through.
      const entry: PinEntry = {
        current_hash: liveHash,
        previous_hashes: [],
        captured_at: new Date().toISOString(),
        captured_via: "first-session",
        signature_list_version: deps.signatureListVersion,
      };
      pinsAfter = upsertToolPin(pinsAfter, serverName, toolName, entry);
      continue;
    }

    if (existing.current_hash === null) {
      // Placeholder entry from a failed install-time capture. Fill it in now.
      const entry: PinEntry = {
        ...existing,
        current_hash: liveHash,
        captured_at: new Date().toISOString(),
        captured_via: "first-session",
        signature_list_version: deps.signatureListVersion,
      };
      pinsAfter = upsertToolPin(pinsAfter, serverName, toolName, entry);
      continue;
    }

    if (existing.current_hash !== liveHash) {
      driftedTools.push({
        toolName,
        expected: existing.current_hash,
        actual: liveHash,
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

  return {
    action: "block",
    findings: driftedTools.map((d) => {
      const safeServer = sanitizeLabel(serverName);
      const safeTool = sanitizeLabel(d.toolName);
      return {
        signature_id: "schema-drift",
        category: "OWASP-MCP-1",
        severity: "critical" as const,
        target: "tool_description" as const,
        matched_text_excerpt: `${safeTool}: ${d.expected.slice(7, 19)}… → ${d.actual.slice(7, 19)}…`,
        remediation:
          `Tool "${safeTool}" schema changed since install (rug-pull suspected). ` +
          `If this is a legitimate server upgrade, run \`mcpm guard accept-drift ${safeServer} --tool ${safeTool} --new-hash ${d.actual}\` ` +
          `(or \`--remove\` to drop the pin entirely).`,
      };
    }),
  };
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
    next = upsertToolPin(next, serverName, t, {
      ...existing,
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
