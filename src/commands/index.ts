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
import { registerImportCommand } from "./import.js";
import { registerServeCommand } from "./serve.js";
import { registerDisableCommand } from "./disable.js";
import { registerEnableCommand } from "./enable.js";
import { registerCompletionsCommand } from "./completions.js";
import { registerAliasCommand } from "./alias.js";

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
export { registerImportCommand, handleImport, checkFirstRun } from "./import.js";
export type { ImportDeps, ImportOptions } from "./import.js";
export { registerServeCommand } from "./serve.js";
export { registerDisableCommand, handleDisable } from "./disable.js";
export type { DisableDeps, DisableOptions } from "./disable.js";
export { registerEnableCommand, handleEnable } from "./enable.js";
export type { EnableDeps, EnableOptions } from "./enable.js";
export { registerCompletionsCommand, handleCompletions } from "./completions.js";
export type { ShellType, CompletionsDeps } from "./completions.js";
export { registerAliasCommand, handleAlias } from "./alias.js";
export type { AliasDeps, AliasOptions } from "./alias.js";

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
  registerImportCommand(program);
  registerServeCommand(program);
  registerDisableCommand(program);
  registerEnableCommand(program);
  registerCompletionsCommand(program);
  registerAliasCommand(program);
}
