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
