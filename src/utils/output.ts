/**
 * Shared stdout output helper.
 * All commands route output through an injectable `output` dep for testability;
 * this function is the production implementation wired at registration time.
 */

export function stdoutOutput(text: string): void {
  process.stdout.write(text + "\n");
}
