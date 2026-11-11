/** Report-only store inventory: no directory creation or legacy-reader changes. */
import { realpath } from "node:fs/promises";
import { isUtf8 } from "node:buffer";
import os from "node:os";
import path from "node:path";
import { z } from "zod";
import { parseJsonObject, readBoundedBytes } from "../config/read-bounded-json.js";
import { CLIENT_IDS } from "../config/paths.js";
import { SERVERS_SCHEMA_VERSION, type InstalledServer } from "./servers.js";

const RowSchema = z.object({
  name: z.string().max(256).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*\/[a-zA-Z0-9][a-zA-Z0-9._-]*$/),
  version: z.string().min(1).max(256).regex(/^[\x20-\x7e]+$/),
  clients: z.array(z.enum(CLIENT_IDS)),
  installedAt: z.iso.datetime({ offset: true }),
});

export interface AuditInventory {
  state: "complete" | "empty" | "incomplete";
  presence: "missing" | "present" | "unknown";
  total: number | null;
  accepted: number;
  issues: { code: "unreadable" | "malformed-json" | "unsupported-shape" | "unsupported-schema" | "invalid-row" | "duplicate-name" | "symlink-skipped" | "not-file" | "too-large"; index?: number }[];
  servers: InstalledServer[];
}

async function readInventoryText(): Promise<string> {
  const home = await realpath(os.homedir());
  const result = await readBoundedBytes(path.join(home, ".mcpm", "servers.json"));
  if (!result.bytes) throw { code: result.state === "missing" ? "ENOENT" : result.state };
  if (!isUtf8(result.bytes)) throw { code: "malformed-json" };
  return result.bytes.toString("utf8");
}

export async function readAuditInventory(
  read: () => Promise<string> = readInventoryText,
): Promise<AuditInventory> {
  const inventory: AuditInventory = { state: "incomplete", presence: "unknown", total: null, accepted: 0, issues: [], servers: [] };
  let text: string;
  try { text = await read(); }
  catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === "ENOENT") return { ...inventory, state: "empty", presence: "missing", total: 0 };
    const code = (error as { code?: string })?.code;
    const reason = code === "symlink-skipped" || code === "not-file" || code === "too-large" || code === "malformed-json" ? code : "unreadable";
    return { ...inventory, issues: [{ code: reason }] };
  }
  inventory.presence = "present";
  // Wrap legacy arrays to reuse the strict object parser and duplicate-key checks.
  const parsed = parseJsonObject(Buffer.from('{"inventory":' + text + '}'));
  if (!parsed || Object.keys(parsed).length !== 1) return { ...inventory, issues: [{ code: "malformed-json" }] };
  const raw = parsed.inventory;
  let rows: unknown[];
  if (Array.isArray(raw)) rows = raw;
  else {
    const container = z.object({ mcpmSchemaVersion: z.number(), servers: z.array(z.unknown()) }).safeParse(raw);
    if (!container.success) return { ...inventory, issues: [{ code: "unsupported-shape" }] };
    if (container.data.mcpmSchemaVersion !== SERVERS_SCHEMA_VERSION) return { ...inventory, issues: [{ code: "unsupported-schema" }] };
    rows = container.data.servers;
  }
  inventory.total = rows.length;
  const names = new Set<string>();
  rows.forEach((row, index) => {
    const parsed = RowSchema.safeParse(row);
    if (!parsed.success) inventory.issues.push({ code: "invalid-row", index });
    else if (names.has(parsed.data.name)) inventory.issues.push({ code: "duplicate-name", index });
    else { names.add(parsed.data.name); inventory.servers.push(parsed.data); }
  });
  inventory.accepted = inventory.servers.length;
  inventory.state = inventory.issues.length > 0 ? "incomplete" : rows.length === 0 ? "empty" : "complete";
  return inventory;
}
