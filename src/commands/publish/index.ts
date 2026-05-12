/**
 * `mcpm publish` command group.
 */

import { Command } from "commander";
import chalk from "chalk";
import { readManifest } from "./manifest.js";
import { handlePublishCheck } from "./check.js";
import { handlePublishSubmit, getTokenFromEnv } from "./submit.js";
import { scanTier1 } from "../../scanner/tier1.js";
import { computeTrustScore } from "../../scanner/trust-score.js";
import { stdoutOutput } from "../../utils/output.js";

export function registerPublishCommand(program: Command): void {
  const pub = program
    .command("publish")
    .description("Publish an MCP server to the official registry");

  pub
    .command("scaffold")
    .description("Create a .mcpm-publish.yaml manifest interactively")
    .action(async () => {
      // Scaffold wizard — minimal interactive prompts
      const { input, select } = await import("@inquirer/prompts");
      const { writeFile } = await import("node:fs/promises");
      const { resolve } = await import("node:path");
      const { stringify } = await import("yaml");

      const name = await input({ message: "Package name (e.g. io.github.you/my-server):" });
      const description = await input({ message: "Short description:" });
      const homepage = await input({ message: "Homepage URL (optional):", default: "" });
      const registryType = await select({
        message: "Registry type:",
        choices: [
          { value: "npm", name: "npm" },
          { value: "pypi", name: "PyPI" },
          { value: "oci", name: "OCI (Docker)" },
        ],
      });
      const identifier = await input({ message: `${registryType} package identifier (e.g. @you/my-server):` });

      const manifest = {
        name,
        description,
        ...(homepage ? { homepage } : {}),
        tags: [],
        package: { registryType, identifier },
      };

      const manifestPath = resolve(process.cwd(), ".mcpm-publish.yaml");
      await writeFile(manifestPath, stringify(manifest), "utf-8");
      stdoutOutput(chalk.green(`\nCreated .mcpm-publish.yaml`));
      stdoutOutput(`Run ${chalk.cyan("mcpm publish check")} to validate before submitting.`);
    });

  pub
    .command("check")
    .description("Dry-run: show trust score and what would be submitted")
    .option("--registry <url>", "Custom registry URL")
    .action(async (opts: { registry?: string }) => {
      await handlePublishCheck(
        { registryUrl: opts.registry },
        { readManifest, scanTier1, computeTrustScore, output: stdoutOutput }
      ).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });

  pub
    .description("Submit to the official MCP registry (requires GITHUB_TOKEN)")
    .option("--registry <url>", "Custom registry URL")
    .action(async (opts: { registry?: string }) => {
      const { submitToRegistry } = await import("../../registry/publish-client.js");
      await handlePublishSubmit(
        { registryUrl: opts.registry },
        {
          readManifest,
          scanTier1,
          computeTrustScore,
          submitToRegistry,
          getToken: getTokenFromEnv,
          output: stdoutOutput,
        }
      ).catch((err: Error) => {
        console.error(chalk.red(err.message));
        process.exit(1);
      });
    });
}
