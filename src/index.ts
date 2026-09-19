// Suppress cli-table3 "padLevels" circular dependency warning.
// Only filter the known noisy warning; let all others propagate normally.
process.on("warning", (w) => {
  if (w.message?.includes("padLevels")) return;
  console.error(w);
});

// A consumer that closes the pipe early (`mcpm guard list-signatures | head -1`,
// `| grep -q`, a paging reader that quits) makes the next write to stdout emit an
// 'error' event. With no listener that is an unhandled 'error' — Node prints a
// 29-line stack and exits 1, so a routine shell idiom looked like an mcpm crash.
// EPIPE means "nobody is reading any more", which is a normal end, not a failure:
// exit 0 quietly. Anything else is a real I/O failure and is rethrown unchanged,
// preserving the previous behaviour for every non-EPIPE case.
for (const stream of [process.stdout, process.stderr]) {
  stream.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EPIPE") process.exit(0);
    throw err;
  });
}

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
