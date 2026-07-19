/**
 * Shared stdout output helper.
 * All commands route output through an injectable `output` dep for testability;
 * this function is the production implementation wired at registration time.
 */

import chalk from "chalk";

export function stdoutOutput(text: string): void {
  process.stdout.write(text + "\n");
}

/**
 * Status-prefixed colorizer for human-readable command output: "  ✓" → green,
 * "  ✗" → red, "  ⚠" → yellow, anything else plain. Wired as the `output` dep
 * for non-JSON/non-report renders (doctor, verify).
 */
export function coloredOutput(text: string): void {
  if (text.startsWith("  ✓")) {
    console.log(chalk.green(text));
  } else if (text.startsWith("  ✗")) {
    console.log(chalk.red(text));
  } else if (text.startsWith("  ⚠")) {
    console.log(chalk.yellow(text));
  } else {
    console.log(text);
  }
}
