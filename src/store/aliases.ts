/**
 * Manages server name aliases in ~/.mcpm/aliases.json.
 *
 * Aliases map short names to full server names, e.g.:
 *   "fs" → "io.github.domdomegg/filesystem-mcp"
 */

import { readJson, writeJson } from "./index.js";

const FILENAME = "aliases.json";

export type AliasMap = Record<string, string>;

/**
 * Returns all aliases. Returns an empty object if none are stored.
 */
export async function getAliases(): Promise<AliasMap> {
  const data = await readJson<AliasMap>(FILENAME);
  return data === null ? {} : { ...data };
}

/**
 * Sets an alias. Overwrites if it already exists.
 */
export async function setAlias(alias: string, serverName: string): Promise<void> {
  const current = await getAliases();
  const updated: AliasMap = { ...current, [alias]: serverName };
  await writeJson(FILENAME, updated);
}

/**
 * Removes an alias. Throws if the alias does not exist.
 */
export async function removeAlias(alias: string): Promise<void> {
  const current = await getAliases();
  if (!Object.prototype.hasOwnProperty.call(current, alias)) {
    throw new Error(`Alias "${alias}" not found.`);
  }
  const { [alias]: _removed, ...remaining } = current;
  await writeJson(FILENAME, remaining);
}

/**
 * Resolves an alias to a server name. Returns the input if no alias exists.
 */
export async function resolveAlias(nameOrAlias: string): Promise<string> {
  const aliases = await getAliases();
  return aliases[nameOrAlias] ?? nameOrAlias;
}
