/**
 * BaseAdapter — shared read/write logic for all config adapters.
 *
 * Concrete adapters specify the root key used for MCP servers
 * ("mcpServers" for Claude Desktop/Cursor/Windsurf, "servers" for VS Code).
 *
 * All writes are atomic: data is written to a .tmp sibling file first,
 * then fs.rename() moves it into place.
 */

import { readFile, writeFile, rename, mkdir } from "fs/promises";
import path from "path";
import type { ClientId } from "../paths.js";
import type { ConfigAdapter, McpServerEntry } from "./index.js";

export abstract class BaseAdapter implements ConfigAdapter {
  abstract readonly clientId: ClientId;
  protected abstract readonly rootKey: string;

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Read the raw config file as a parsed object.
   * Returns an empty object `{}` when the file does not exist (ENOENT).
   * Re-throws for all other errors (EACCES, malformed JSON, etc.).
   */
  private async readRaw(configPath: string): Promise<Record<string, unknown>> {
    let raw: string;
    try {
      raw = await readFile(configPath, "utf-8");
    } catch (err) {
      if (isEnoent(err)) {
        return {};
      }
      throw err;
    }

    // JSON.parse throws on malformed input — let it propagate.
    return JSON.parse(raw) as Record<string, unknown>;
  }

  /**
   * Write `data` to `configPath` atomically via a .tmp sibling.
   * If `previousContent` is non-empty, writes a .bak backup first.
   * Creates parent directories if they do not exist.
   */
  private async writeAtomic(
    configPath: string,
    data: Record<string, unknown>,
    previousContent: Record<string, unknown>
  ): Promise<void> {
    const dir = path.dirname(configPath);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    if (Object.keys(previousContent).length > 0) {
      await writeFile(`${configPath}.bak`, JSON.stringify(previousContent, null, 2), {
        encoding: "utf-8",
        mode: 0o600,
      });
    }

    const tmpPath = `${configPath}.tmp`;
    await writeFile(tmpPath, JSON.stringify(data, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
    });
    await rename(tmpPath, configPath);
  }

  // ---------------------------------------------------------------------------
  // ConfigAdapter implementation
  // ---------------------------------------------------------------------------

  async read(configPath: string): Promise<Record<string, McpServerEntry>> {
    const raw = await this.readRaw(configPath);
    const servers = raw[this.rootKey];
    if (servers == null || typeof servers !== "object" || Array.isArray(servers)) {
      return {};
    }
    // Return a shallow copy — callers may not mutate our internal state.
    return { ...(servers as Record<string, McpServerEntry>) };
  }

  async addServer(
    configPath: string,
    name: string,
    entry: McpServerEntry,
    options?: { force?: boolean }
  ): Promise<void> {
    // readRaw returns {} for ENOENT and re-throws all other errors,
    // so we can call it directly here.
    const raw = await this.readRaw(configPath);

    const existing = (raw[this.rootKey] ?? {}) as Record<string, McpServerEntry>;

    if (Object.prototype.hasOwnProperty.call(existing, name) && !options?.force) {
      throw new Error(
        `Server "${name}" already exists in ${this.clientId} config. Use --force to overwrite.`
      );
    }

    // Immutable update — never mutate existing or entry.
    const updatedServers: Record<string, McpServerEntry> = {
      ...existing,
      [name]: { ...entry },
    };

    const updated: Record<string, unknown> = {
      ...raw,
      [this.rootKey]: updatedServers,
    };

    await this.writeAtomic(configPath, updated, raw);
  }

  async removeServer(configPath: string, name: string): Promise<void> {
    const raw = await this.readRaw(configPath);
    const existing = (raw[this.rootKey] ?? {}) as Record<string, McpServerEntry>;

    if (!Object.prototype.hasOwnProperty.call(existing, name)) {
      throw new Error(
        `Server "${name}" not found in ${this.clientId} config.`
      );
    }

    // Build a new servers object without the removed key.
    const { [name]: _removed, ...remaining } = existing;

    const updated: Record<string, unknown> = {
      ...raw,
      [this.rootKey]: remaining,
    };

    await this.writeAtomic(configPath, updated, raw);
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isEnoent(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}
