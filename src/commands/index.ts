/**
 * Barrel export for src/commands/.
 *
 * Re-exports all register functions so src/index.ts can import from one place.
 * Also exports a convenience registerCommands() that registers all commands at once.
 */

import type { Command } from "commander";
import { registerSearch } from "./search.js";
import { registerInfo } from "./info.js";
import { registerList } from "./list.js";

export { registerSearch } from "./search.js";
export { registerInfo } from "./info.js";
export { registerList } from "./list.js";
export { registerRemoveCommand } from "./remove.js";
export { registerDoctorCommand } from "./doctor.js";

/**
 * Registers all commands on the given Commander program.
 * Commands are registered in the order they appear in `mcpm --help`.
 */
export function registerCommands(program: Command): void {
  registerSearch(program);
  registerInfo(program);
  registerList(program);
}
