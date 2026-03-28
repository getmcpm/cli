/**
 * Barrel export for src/commands/.
 *
 * Re-exports all register functions so src/index.ts can import from one place.
 * Also exports a convenience registerCommands() that registers all commands at once.
 */

import type { Command } from "commander";
import { registerSearch } from "./search.js";
import { registerInstallCommand } from "./install.js";
import { registerInfo } from "./info.js";
import { registerList } from "./list.js";
import { registerRemoveCommand } from "./remove.js";
import { registerDoctorCommand } from "./doctor.js";
import { registerAuditCommand } from "./audit.js";
import { registerUpdateCommand } from "./update.js";
import { registerInitCommand } from "./init.js";

export { registerSearch } from "./search.js";
export { registerInstallCommand, handleInstall, resolveInstallEntry, formatTrustScore } from "./install.js";
export type { InstallDeps, InstallOptions } from "./install.js";
export { registerInfo } from "./info.js";
export { registerList } from "./list.js";
export { registerRemoveCommand } from "./remove.js";
export { registerDoctorCommand } from "./doctor.js";
export { registerAuditCommand } from "./audit.js";
export { registerUpdateCommand } from "./update.js";
export { registerInitCommand } from "./init.js";
export { PACKS } from "./init.js";
export type { PackDefinition, InitDeps, InitOptions } from "./init.js";

export function registerCommands(program: Command): void {
  registerSearch(program);
  registerInstallCommand(program);
  registerInfo(program);
  registerList(program);
  registerRemoveCommand(program);
  registerDoctorCommand(program);
  registerAuditCommand(program);
  registerUpdateCommand(program);
  registerInitCommand(program);
}
