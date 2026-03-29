/**
 * Shared confirm prompt utility.
 * Returns a function that prompts the user with a [y/N] question over stdin.
 */

import * as readline from "node:readline";

export function createConfirm(): (message: string) => Promise<boolean> {
  return (message: string): Promise<boolean> =>
    new Promise((resolve) => {
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
