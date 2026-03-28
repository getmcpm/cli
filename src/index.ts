import { Command } from "commander";
import { registerSearch, registerInfo, registerRemoveCommand, registerDoctorCommand } from "./commands/index.js";

const program = new Command();

program
  .name("mcpm")
  .description("MCP package manager — search, install, and audit MCP servers")
  .version("0.1.0");

registerSearch(program);
registerInfo(program);
registerRemoveCommand(program);
registerDoctorCommand(program);

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
