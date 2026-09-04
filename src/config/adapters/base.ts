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
import { z } from "zod";
import type { ClientId } from "../paths.js";
import type { ConfigAdapter, McpServerEntry } from "./index.js";
import { sanitizeForTerminal } from "../../guard/sanitize.js";

// #23: read() used to cast `raw[rootKey]` straight to Record<string, McpServerEntry>
// with only an object/array check on the CONTAINER. A per-entry shape mismatch
// from hand-edited or IDE-mangled config — e.g. `args: "bad"` instead of
// `["bad"]` — passed through untouched: downstream code that spreads `args`
// (the guard wrap transform) would iterate the STRING's characters instead of
// array elements. z.looseObject preserves any extra fields a client writes on
// an entry (matches the pre-existing spread-copy behavior for well-formed
// entries); only entries that fail the known-field shapes are dropped.
const McpServerEntrySchema = z.looseObject({
  command: z.string().optional(),
  args: z.array(z.string()).optional(),
  env: z.record(z.string(), z.string()).optional(),
  url: z.string().optional(),
  headers: z.record(z.string(), z.string()).optional(),
  disabled: z.boolean().optional(),
});

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

  async read(
    configPath: string,
    // #23 follow-up (adversarial review): a bare stderr write is invisible to
    // callers that build a STRUCTURED report over the skip (guard/orchestrator.ts's
    // `skipped` list, commands/doctor.ts's DoctorIssue) and un-mockable from the
    // ~15 call sites, incl. two inside the MCP server surface (server/handlers.ts).
    // Injectable — same seam as scanner/tier2.ts's onWarn — so a caller can route
    // the skip into its own reporting instead of (or in addition to) stderr.
    // Default preserves the original stderr-warning behavior for every caller
    // that doesn't opt in.
    // #59 closed the remaining unwired callers: diff (a dropped entry was
    // reported "missing"), export (silently absent from a stack file the user
    // keeps), import (silently absent from the pick-list), list (silently
    // absent from the inventory, incl. `--json`), sync/doctor's drift model (a
    // client that HAS the server was reported as lacking it), update (the
    // force re-write discarded the entry's env block), and up --strict (left
    // behind while reporting a clean reconciliation). guard/cli.ts's two sites
    // pass a NO-OP on purpose — the orchestrator names the same entry in the
    // same invocation, so the default would print it twice; see there.
    // #23 follow-up (adversarial review): name is config-supplied (attacker-
    // controllable) and reaches the real terminal via this default — sanitize
    // it the same way doctor.ts/guard's cli.ts already do for this class of
    // value, so a name like `srv\x1b]0;evil\x07` can't inject terminal escapes.
    // #59: the RAW entry is passed alongside the name. A caller that is about
    // to OVERWRITE this entry needs to know what it would discard, and the
    // validated map cannot tell it — the entry is not in there. Deliberately
    // `unknown`: it failed validation, so a consumer must narrow whatever
    // single field it needs and must not spread it.
    onSkip: (name: string, raw: unknown) => void = (name) =>
      process.stderr.write(
        `mcpm: skipping malformed server entry "${sanitizeForTerminal(name)}" in ${configPath} ` +
          `(${this.clientId}): does not match the expected shape.\n`,
      ),
  ): Promise<Record<string, McpServerEntry>> {
    const raw = await this.readRaw(configPath);
    const servers = raw[this.rootKey];
    if (servers == null || typeof servers !== "object" || Array.isArray(servers)) {
      return {};
    }
    const out: Record<string, McpServerEntry> = {};
    for (const [name, entry] of Object.entries(servers as Record<string, unknown>)) {
      const parsed = McpServerEntrySchema.safeParse(entry);
      if (parsed.success) {
        out[name] = parsed.data;
      } else {
        // #23: skip rather than propagate a malformed entry — better an
        // absent server than one silently corrupting a downstream transform
        // (e.g. spreading a string `args` char-by-char in guard/wrap.ts).
        onSkip(name, entry);
      }
    }
    return out;
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
    const existing = (raw[this.rootKey] ?? {}) as Record<string, unknown>;

    if (!Object.prototype.hasOwnProperty.call(existing, name)) {
      throw new Error(
        `Server "${name}" not found in ${this.clientId} config.`
      );
    }

    // #23 follow-up (adversarial review): this used to spread `existing[name]`
    // unconditionally. For a raw entry that is not a plain object (e.g. a bare
    // string — the exact shape read() now drops elsewhere in this class), the
    // object spread iterates its characters ({"0":"a","1":"b",...}), silently
    // corrupting the entry — the same class of bug #23 exists to prevent, one
    // level up. Fail loudly instead: this can't be safely merged/toggled.
    const rawEntry = existing[name];
    if (rawEntry === null || typeof rawEntry !== "object" || Array.isArray(rawEntry)) {
      throw new Error(
        `Server "${name}" in ${this.clientId} config is not a valid object — cannot toggle. ` +
          `Fix the entry by hand, or run "mcpm remove ${name}" to clear it.`,
      );
    }

    const entry: McpServerEntry = { ...(rawEntry as McpServerEntry) };
    if (disabled) {
      entry.disabled = true;
    } else {
      delete entry.disabled;
    }

    // Sibling entries are passed through unchanged (same as before this
    // guard was added) — only the entry actually being toggled (`entry`,
    // just validated above) is shape-checked.
    const updatedServers: Record<string, McpServerEntry> = {
      ...(existing as Record<string, McpServerEntry>),
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
