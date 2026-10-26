import { BaseAdapter } from "./base.js";
import type { ClientId } from "../paths.js";
import type { McpServerEntry } from "./index.js";

const DISABLED_KEY = "_mcpmDisabledServers";

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class CursorAdapter extends BaseAdapter {
  readonly clientId: ClientId = "cursor";
  protected readonly rootKey = "mcpServers";

  private async readPhysical(configPath: string): Promise<Record<string, unknown>> {
    const raw = await super.readRaw(configPath);
    if (!isObject(raw)) throw new Error("Invalid Cursor configuration; expected an object.");
    const active = raw.mcpServers === undefined ? {} : raw.mcpServers;
    const parked = raw[DISABLED_KEY] === undefined ? {} : raw[DISABLED_KEY];
    if (!isObject(active) || !isObject(parked)) {
      throw new Error("Invalid Cursor server maps; cannot safely manage disabled servers.");
    }
    return raw;
  }

  protected override async readRaw(configPath: string): Promise<Record<string, unknown>> {
    const raw = await this.readPhysical(configPath);
    const active = (raw.mcpServers ?? {}) as Record<string, unknown>;
    const parked = (raw[DISABLED_KEY] ?? {}) as Record<string, unknown>;
    const servers: Record<string, unknown> = Object.create(null);
    for (const [name, entry] of Object.entries(active)) {
      // Cursor ignores this legacy flag; only parked entries are disabled.
      if (isObject(entry) && typeof entry.disabled === "boolean") {
        const { disabled: _disabled, ...rest } = entry;
        servers[name] = rest;
      } else {
        servers[name] = entry;
      }
    }
    for (const [name, entry] of Object.entries(parked)) {
      if (Object.hasOwn(servers, name) || !isObject(entry)) {
        throw new Error("Ambiguous or malformed Cursor disabled server; repair the server maps first.");
      }
      servers[name] = { ...entry, disabled: true };
    }
    return { ...raw, mcpServers: servers };
  }

  protected override async writeAtomic(
    configPath: string,
    data: Record<string, unknown>,
    serverName: string,
  ): Promise<void> {
    const original = await this.readPhysical(configPath);
    // Logical reads normalize legacy flags; only the target may change on disk.
    const active = Object.assign(Object.create(null), original.mcpServers) as Record<string, unknown>;
    const parked = Object.assign(Object.create(null), original[DISABLED_KEY]) as Record<string, unknown>;
    delete active[serverName];
    delete parked[serverName];
    const servers = data.mcpServers as Record<string, unknown>;
    if (Object.hasOwn(servers, serverName)) {
      const entry = servers[serverName];
      if (isObject(entry) && entry.disabled === true) {
        const { disabled: _disabled, ...rest } = entry;
        parked[serverName] = rest;
      } else {
        active[serverName] = entry;
      }
    }
    const physical: Record<string, unknown> = { ...original, mcpServers: active };
    delete physical[DISABLED_KEY];
    if (Object.keys(parked).length) physical[DISABLED_KEY] = parked;
    await super.writeAtomic(configPath, physical, serverName);
  }

  override async addServer(configPath: string, name: string, entry: McpServerEntry, options?: { force?: boolean }): Promise<void> {
    if (options?.force) entry = await this.preserveDisabled(configPath, name, entry);
    await super.addServer(configPath, name, entry, options);
  }

  override async replaceServer(configPath: string, name: string, entry: McpServerEntry): Promise<void> {
    await super.replaceServer(configPath, name, await this.preserveDisabled(configPath, name, entry));
  }

  private async preserveDisabled(configPath: string, name: string, entry: McpServerEntry): Promise<McpServerEntry> {
    const raw = await this.readRaw(configPath);
    const servers = raw.mcpServers as Record<string, unknown>;
    const previous = Object.hasOwn(servers, name) ? servers[name] : undefined;
    return isObject(previous) && previous.disabled === true ? { ...entry, disabled: true } : entry;
  }
}
