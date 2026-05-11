/**
 * Strips PII from telemetry events before queuing.
 * Only command, outcome, error code, version, and platform are retained.
 * Server names, file paths, and identifiers are never included.
 */

/** Allowlist for errorCode — must be an uppercase constant, not a free-form string. */
const ERROR_CODE_RE = /^[A-Z_]{1,64}$/;

export interface RawTelemetryEvent {
  command: string;
  outcome: "success" | "error";
  /** Must match [A-Z_]{1,64} or it is dropped to prevent PII via error messages. */
  errorCode?: string;
  mcpmVersion: string;
  nodeVersion: string;
  platform: string;
}

export interface AnonTelemetryEvent {
  command: string;
  outcome: "success" | "error";
  errorCode?: string;
  mcpmVersion: string;
  nodeVersion: string;
  platform: string;
  ts: string;
}

export function anonymize(raw: RawTelemetryEvent): AnonTelemetryEvent {
  const event: AnonTelemetryEvent = {
    command: raw.command,
    outcome: raw.outcome,
    mcpmVersion: raw.mcpmVersion,
    nodeVersion: raw.nodeVersion,
    platform: raw.platform,
    ts: new Date().toISOString(),
  };
  if (raw.errorCode && ERROR_CODE_RE.test(raw.errorCode)) event.errorCode = raw.errorCode;
  return event;
}
