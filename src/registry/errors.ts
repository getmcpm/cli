/**
 * Error hierarchy for the registry client.
 *
 * RegistryError (base)
 * ├── NetworkError     — fetch failed, timeout, connection refused
 * ├── NotFoundError    — HTTP 404
 * └── ValidationError — malformed JSON or Zod parse failure
 */

export class RegistryError extends Error {
  readonly statusCode: number | undefined;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = "RegistryError";
    this.statusCode = statusCode;
    // Maintain proper prototype chain in transpiled environments.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class NetworkError extends RegistryError {
  readonly cause: Error;

  constructor(message: string, cause: Error) {
    super(message);
    this.name = "NetworkError";
    this.cause = cause;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class NotFoundError extends RegistryError {
  constructor(serverName: string) {
    super(`Server not found: ${serverName}`, 404);
    this.name = "NotFoundError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ValidationError extends RegistryError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ValidationError";
    if (cause !== undefined) {
      (this as { validationCause?: unknown }).validationCause = cause;
    }
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Error classification for user/agent-facing surfaces
// ---------------------------------------------------------------------------

/** The distinguishable registry failure classes a caller can act on. */
export type RegistryErrorKind =
  | "not-found"
  | "unrecognised-response"
  | "unavailable"
  | "unknown";

export interface RegistryErrorDescription {
  readonly kind: RegistryErrorKind;
  readonly message: string;
}

/**
 * Classify a thrown registry error into an actionable kind + message.
 *
 * Every surface that catches a registry fetch (audit, update, outdated, and the
 * `mcpm_audit` MCP tool) used to collapse all four classes into the single label
 * "Registry unavailable", which is true only for `NetworkError`. A 404 is the
 * E9a delisting signal — a real, actionable fact about the server — and a
 * `ValidationError` means the registry answered with a shape mcpm does not
 * recognise, which is a fact about the registry, not about the server. Reporting
 * either as "unavailable" sends the reader to look for a network problem that
 * does not exist. (maintainer backlog #92)
 *
 * Pure: returns a new object, never mutates or rethrows.
 */
export function describeRegistryError(err: unknown): RegistryErrorDescription {
  if (err instanceof NotFoundError) {
    return {
      kind: "not-found",
      message:
        "Not found in the registry (404) — the server may have been delisted or renamed",
    };
  }
  if (err instanceof ValidationError) {
    return {
      kind: "unrecognised-response",
      message:
        "Registry returned a response mcpm could not parse — the API may have changed",
    };
  }
  if (err instanceof NetworkError) {
    return { kind: "unavailable", message: "Registry unavailable — could not fetch metadata" };
  }
  if (err instanceof RegistryError) {
    const status = err.statusCode;
    return {
      kind: "unavailable",
      message:
        status === undefined
          ? "Registry unavailable — could not fetch metadata"
          : `Registry unavailable — the registry returned HTTP ${status}`,
    };
  }
  return {
    kind: "unknown",
    message: `Could not fetch registry metadata: ${err instanceof Error ? err.message : String(err)}`,
  };
}
