/**
 * Telemetry queue — append-only JSON array, flushed asynchronously.
 *
 * Disabled when MCPM_NO_TRACK=1 or DO_NOT_TRACK=1 (cross-ecosystem standard).
 * Default is off until the first-run opt-in prompt is answered.
 *
 * Queue write failures are silently swallowed — telemetry must never crash mcpm.
 */

import { readJson, writeJson } from "../store/index.js";
import { anonymize, type RawTelemetryEvent, type AnonTelemetryEvent } from "./anonymize.js";

const QUEUE_FILE = "telemetry-queue.json";
const MAX_QUEUE_SIZE = 200;

export function isTelemetryEnabled(): boolean {
  if (process.env.MCPM_NO_TRACK === "1") return false;
  if (process.env.DO_NOT_TRACK === "1") return false;
  return false;
}

/**
 * Append one anonymized event to the queue.
 * Never throws — silently drops on any I/O failure.
 */
export async function enqueueEvent(raw: RawTelemetryEvent): Promise<void> {
  if (!isTelemetryEnabled()) return;

  try {
    const existing = (await readJson<AnonTelemetryEvent[]>(QUEUE_FILE)) ?? [];
    await writeJson(QUEUE_FILE, [...existing.slice(-(MAX_QUEUE_SIZE - 1)), anonymize(raw)]);
  } catch {
    // Swallow — disk full / permissions must not crash mcpm
  }
}
