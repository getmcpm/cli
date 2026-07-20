/**
 * Shared confirm prompt utility.
 * Prompts the user with a [y/N] question over stdin.
 */

import * as readline from "node:readline";

export function confirm(message: string): Promise<boolean> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(`${message} [y/N] `, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === "y");
    });
  });
}
