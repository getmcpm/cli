import { Command } from "commander";

const program = new Command();

program
  .name("mcpm")
  .description("MCP package manager — search, install, and audit MCP servers")
  .version("0.1.0");

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
