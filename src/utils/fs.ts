/**
 * Shared filesystem utilities.
 */

/**
 * Returns true if the error is an ENOENT (file not found) error.
 */
export function isEnoent(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}
