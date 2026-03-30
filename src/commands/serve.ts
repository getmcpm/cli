/**
 * `mcpm serve` command — starts mcpm as an MCP server over stdio.
 *
 * Exposes search, install, info, list, remove, audit, doctor, and setup
 * as MCP tools that AI agents can call programmatically.
 */

import { Command } from "commander";

export function registerServeCommand(program: Command): void {
  program
    .command("serve")
    .description("Start mcpm as an MCP server (stdio transport)")
    .action(async () => {
      const { startServer } = await import("../server/index.js");
      await startServer();
    });
}
