/**
 * BaseAdapter — shared read/write logic for all config adapters.
 *
 * Concrete adapters specify the root key used for MCP servers
 * ("mcpServers" for Claude Desktop/Cursor/Windsurf, "servers" for VS Code).
 *
 * All writes are atomic: data is written to a .tmp sibling file first,
 * then fs.rename() moves it into place.
 */

import { readFile, writeFile, rename, mkdir, lstat, unlink } from "fs/promises";
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
    // #26: refuse to traverse a symlinked config path. We check before the
    // read so an attacker who points <config> at a sensitive file can neither
    // have its bytes echoed into the .bak nor have our write land on the
    // target. lstat does not follow the final symlink.
    await assertNotSymlink(configPath);

    let raw: string;
    try {
      raw = await readFile(configPath, "utf-8");
    } catch (err) {
      if (isEnoent(err)) {
        return {};
      }
      throw err;
    }

    // Empty files are treated as empty configs (common when an IDE creates
    // the file but hasn't written content yet).
    if (raw.trim() === "") {
      return {};
    }

    // JSON.parse throws on malformed input — let it propagate.
    return JSON.parse(raw) as Record<string, unknown>;
  }

  /**
   * Write `data` to `configPath` atomically via a .tmp sibling.
   *
   * Backup (#25): the .bak preserves the RAW original file bytes (not a
   * re-serialized copy of the parsed object, which would lose formatting,
   * key order, and JSONC comments). It is written exactly ONCE — if a .bak
   * already exists it is never overwritten, so the user's pre-mcpm config
   * state survives any number of later mcpm operations.
   *
   * Symlink safety (#26): all sibling writes are exclusive (flag "wx" =
   * O_CREAT|O_EXCL), mirroring the idiom in src/guard/pins.ts &
   * src/guard/policy.ts. O_EXCL refuses to open through a pre-placed
   * symlink (fails EEXIST even for a dangling link), so an attacker who
   * pre-creates `<config>.bak`/`.tmp` as a symlink to a sensitive file
   * cannot redirect mcpm's write onto the link target. We also lstat the
   * config path itself and refuse to write through a symlinked config.
   *
   * Creates parent directories if they do not exist.
   */
  private async writeAtomic(
    configPath: string,
    data: Record<string, unknown>
  ): Promise<void> {
    const dir = path.dirname(configPath);
    await mkdir(dir, { recursive: true, mode: 0o700 });

    // #26: refuse to write through a symlinked config path. lstat does not
    // follow the final symlink, so we can detect it before the rename lands.
    // (readRaw already enforces this on the read path; repeated here as
    // defense-in-depth for any caller reaching writeAtomic directly.)
    await assertNotSymlink(configPath);

    // #25: back up the RAW original bytes exactly once. Skip if the config
    // does not exist yet, and never clobber an existing .bak. The exclusive
    // "wx" flag (#26) means a concurrent/ pre-placed .bak symlink fails with
    // EEXIST rather than redirecting the write.
    let original: string | null = null;
    try {
      original = await readFile(configPath, "utf-8");
    } catch (err) {
      if (!isEnoent(err)) throw err;
    }
    if (original !== null) {
      try {
        await writeFile(`${configPath}.bak`, original, {
          encoding: "utf-8",
          mode: 0o600,
          flag: "wx",
        });
      } catch (err) {
        // EEXIST = a .bak is already present: write-once, leave it intact.
        if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      }
    }

    // #26: write the temp file EXCLUSIVELY. Unlink any stale .tmp first so a
    // leftover real file from a crashed run does not cause a false EEXIST;
    // unlinking a pre-placed symlink only removes the link, not its target,
    // and the subsequent "wx" open then creates a fresh, unfollowed inode.
    const tmpPath = `${configPath}.tmp`;
    try {
      await unlink(tmpPath);
    } catch (err) {
      if (!isEnoent(err)) throw err;
    }
    await writeFile(tmpPath, JSON.stringify(data, null, 2), {
      encoding: "utf-8",
      mode: 0o600,
      flag: "wx",
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

    await this.writeAtomic(configPath, updated);
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

    await this.writeAtomic(configPath, updated);
  }

  async setServerDisabled(configPath: string, name: string, disabled: boolean): Promise<void> {
    const raw = await this.readRaw(configPath);
    const existing = (raw[this.rootKey] ?? {}) as Record<string, McpServerEntry>;

    if (!Object.prototype.hasOwnProperty.call(existing, name)) {
      throw new Error(
        `Server "${name}" not found in ${this.clientId} config.`
      );
    }

    const entry = { ...existing[name] };
    if (disabled) {
      entry.disabled = true;
    } else {
      delete entry.disabled;
    }

    const updatedServers: Record<string, McpServerEntry> = {
      ...existing,
      [name]: entry,
    };

    const updated: Record<string, unknown> = {
      ...raw,
      [this.rootKey]: updatedServers,
    };

    await this.writeAtomic(configPath, updated);
  }

  async replaceServer(configPath: string, name: string, entry: McpServerEntry): Promise<void> {
    const raw = await this.readRaw(configPath);
    const existing = (raw[this.rootKey] ?? {}) as Record<string, McpServerEntry>;

    if (!Object.prototype.hasOwnProperty.call(existing, name)) {
      throw new Error(`Server "${name}" not found in ${this.clientId} config.`);
    }

    const updatedServers: Record<string, McpServerEntry> = {
      ...existing,
      [name]: { ...entry },
    };

    const updated: Record<string, unknown> = {
      ...raw,
      [this.rootKey]: updatedServers,
    };

    await this.writeAtomic(configPath, updated);
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

/**
 * #26: throw if `targetPath` is a symlink. A missing path (ENOENT) is fine —
 * there is nothing to traverse. lstat does not follow the final component, so
 * this detects a symlinked config/.tmp/.bak before any read or write follows
 * it onto an attacker-chosen target.
 */
async function assertNotSymlink(targetPath: string): Promise<void> {
  let st: Awaited<ReturnType<typeof lstat>>;
  try {
    st = await lstat(targetPath);
  } catch (err) {
    if (isEnoent(err)) return;
    throw err;
  }
  if (st.isSymbolicLink()) {
    throw new Error(`Refusing to write config through a symlink: ${targetPath}`);
  }
}
