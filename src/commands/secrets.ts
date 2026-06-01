/**
 * `mcpm secrets` command handler.
 *
 * Manages encrypted credentials for MCP servers, stored AES-GCM-encrypted in
 * ~/.mcpm/secrets.enc.json (see store/keychain.ts). Instead of writing API
 * keys as plaintext into client config files, a server's env can reference a
 * stored secret via a `mcpm:keychain:server/KEY` placeholder, which
 * `mcpm guard run --inner` resolves to the real value at launch time.
 *
 *   mcpm secrets set <server> <KEY>    # prompts for the value (masked)
 *   mcpm secrets list [server]         # key names only — never values
 *   mcpm secrets get <server> <KEY>    # requires --reveal
 *   mcpm secrets rm  <server> <KEY>
 */

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import { password, confirm } from "@inquirer/prompts";
import { stdoutOutput } from "../utils/output.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SecretsDeps {
  setSecret: (server: string, key: string, value: string) => Promise<void>;
  getSecret: (server: string, key: string) => Promise<string | null>;
  deleteSecret: (server: string, key: string) => Promise<void>;
  listAll: () => Promise<Record<string, string[]>>;
  promptValue: (label: string) => Promise<string>;
  confirmRemove: (label: string) => Promise<boolean>;
  output: (text: string) => void;
}

export interface SecretsGetOptions {
  reveal?: boolean;
}

export interface SecretsRemoveOptions {
  yes?: boolean;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export async function handleSecretsSet(
  server: string,
  key: string,
  deps: SecretsDeps
): Promise<void> {
  const value = await deps.promptValue(`${key} value`);
  if (value.length === 0) {
    throw new Error("Secret value must not be empty.");
  }
  await deps.setSecret(server, key, value);
  deps.output(
    `Stored secret '${server}/${key}'. Reference it in a server's env as ` +
      `${chalk.cyan(`mcpm:keychain:${server}/${key}`)} ` +
      `(resolved by mcpm guard at launch).`
  );
}

export async function handleSecretsList(
  server: string | undefined,
  deps: SecretsDeps
): Promise<void> {
  const all = await deps.listAll();
  const grouped = server
    ? server in all
      ? { [server]: all[server] }
      : {}
    : all;
  const entries = Object.entries(grouped);

  if (entries.length === 0) {
    deps.output(
      server
        ? `No secrets stored for '${server}'.`
        : "No secrets stored. Add one: mcpm secrets set <server> <KEY>"
    );
    return;
  }

  const table = new Table({
    head: [chalk.cyan("Server"), chalk.cyan("Keys")],
    style: { head: [], border: [] },
  });
  for (const [name, keys] of entries) {
    table.push([chalk.white(name), chalk.yellow([...keys].sort().join(", "))]);
  }
  deps.output(table.toString());
}

export async function handleSecretsGet(
  server: string,
  key: string,
  options: SecretsGetOptions,
  deps: SecretsDeps
): Promise<void> {
  if (!options.reveal) {
    throw new Error(
      "Refusing to print a secret value. Re-run with --reveal to confirm you want it on stdout."
    );
  }
  const value = await deps.getSecret(server, key);
  if (value === null) {
    throw new Error(`No secret stored for '${server}/${key}'.`);
  }
  deps.output(value);
}

export async function handleSecretsRemove(
  server: string,
  key: string,
  options: SecretsRemoveOptions,
  deps: SecretsDeps
): Promise<void> {
  if (!options.yes) {
    const confirmed = await deps.confirmRemove(`${server}/${key}`);
    if (!confirmed) {
      deps.output("Aborted.");
      return;
    }
  }
  await deps.deleteSecret(server, key);
  deps.output(`Removed secret '${server}/${key}'.`);
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

async function buildDefaultDeps(): Promise<SecretsDeps> {
  const { setSecret, getSecret, deleteSecret, listAll } = await import(
    "../store/keychain.js"
  );
  return {
    setSecret,
    getSecret,
    deleteSecret,
    listAll,
    promptValue: (label) => password({ message: `${label}:` }),
    confirmRemove: (label) =>
      confirm({ message: `Delete secret '${label}'?`, default: false }),
    output: stdoutOutput,
  };
}

async function runWithDeps(action: (deps: SecretsDeps) => Promise<void>): Promise<void> {
  try {
    const deps = await buildDefaultDeps();
    await action(deps);
  } catch (err) {
    console.error(chalk.red((err as Error).message));
    process.exit(1);
  }
}

export function registerSecretsCommand(program: Command): void {
  const secrets = program
    .command("secrets")
    .description("Manage encrypted credentials for MCP servers");

  secrets
    .command("set <server> <key>")
    .description("Store an encrypted secret (prompts for the value)")
    .action((server: string, key: string) =>
      runWithDeps((deps) => handleSecretsSet(server, key, deps))
    );

  secrets
    .command("list [server]")
    .description("List stored secret keys (values are never shown)")
    .action((server: string | undefined) =>
      runWithDeps((deps) => handleSecretsList(server, deps))
    );

  secrets
    .command("get <server> <key>")
    .description("Print a decrypted secret to stdout (requires --reveal)")
    .option("--reveal", "confirm you want the plaintext printed to stdout")
    .action((server: string, key: string, options: SecretsGetOptions) =>
      runWithDeps((deps) => handleSecretsGet(server, key, options, deps))
    );

  secrets
    .command("rm <server> <key>")
    .alias("remove")
    .description("Delete a stored secret")
    .option("-y, --yes", "skip the confirmation prompt")
    .action((server: string, key: string, options: SecretsRemoveOptions) =>
      runWithDeps((deps) => handleSecretsRemove(server, key, options, deps))
    );
}
