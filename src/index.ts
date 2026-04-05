// Suppress cli-table3 "padLevels" circular dependency warning.
// Only filter the known noisy warning; let all others propagate normally.
process.on("warning", (w) => {
  if (w.message?.includes("padLevels")) return;
  console.error(w);
});

import { Command } from "commander";
import { registerCommands } from "./commands/index.js";

const program = new Command();

program
  .name("mcpm")
  .description("MCP package manager — search, install, and audit MCP servers")
  .version(__PKG_VERSION__);

registerCommands(program);

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${message}\n`);
  process.exit(1);
});
