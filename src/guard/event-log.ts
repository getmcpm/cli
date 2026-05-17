/**
 * Best-effort append-only JSONL writer for ~/.mcpm/guard-events.jsonl
 * (v0.5.0 Step 10).
 *
 * Each event is one line of JSON. Write failures are logged once to stderr
 * but never block the relay — event logging is observability, not enforcement.
 * Users tail/filter via `jq` (recipes in docs/GUARD.md).
 *
 * Rotation is intentionally not implemented for v0.5.0 (TODOS #25 covers
 * v0.5.1 rotation policy). Users with noisy servers can `> ~/.mcpm/guard-events.jsonl`.
 */

import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { getStorePath } from "../store/index.js";
import type { GuardEvent } from "./relay.js";
import { sanitizeForTerminal } from "./sanitize.js";

const EVENT_LOG_FILENAME = "guard-events.jsonl";

let _warnedOnFailure = false;

async function eventLogPath(): Promise<string> {
  return path.join(await getStorePath(), EVENT_LOG_FILENAME);
}

export interface EventLogEntry {
  readonly ts: string;
  readonly server_name: string;
  readonly direction: GuardEvent["direction"];
  readonly action: GuardEvent["action"];
  readonly findings: ReadonlyArray<{
    readonly signature_id: string;
    readonly category: string;
    readonly severity: string;
    readonly target: string;
    readonly matched_text_excerpt: string;
  }>;
}

/**
 * Build the JSONL entry from a guard event + server name. Pure function.
 * Server name is sanitized to strip ANSI / control chars; matched-text
 * excerpts are already truncated to 200 chars by the pattern engine.
 */
export function buildEventLogEntry(event: GuardEvent, serverName: string): EventLogEntry {
  return {
    ts: event.ts,
    server_name: sanitizeForTerminal(serverName),
    direction: event.direction,
    action: event.action,
    findings: event.findings.map((f) => ({
      signature_id: f.signature_id,
      category: f.category,
      severity: f.severity,
      target: f.target,
      matched_text_excerpt: f.matched_text_excerpt,
    })),
  };
}

/**
 * Append a single event to the log. Best-effort: warns once on persistent
 * failure (e.g. read-only home dir) and continues.
 */
export async function appendEvent(event: GuardEvent, serverName: string): Promise<void> {
  try {
    const filePath = await eventLogPath();
    await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const line = `${JSON.stringify(buildEventLogEntry(event, serverName))}\n`;
    await appendFile(filePath, line, { encoding: "utf-8", mode: 0o600 });
  } catch (err) {
    if (!_warnedOnFailure) {
      _warnedOnFailure = true;
      process.stderr.write(
        `[mcpm-guard] event log write failed (logging will continue silently): ${err instanceof Error ? err.message : String(err)}\n`,
      );
    }
  }
}
