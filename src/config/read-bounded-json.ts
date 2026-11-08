/** Bounded, strict JSON snapshot reader shared by non-executing configuration checks. */
import { isUtf8 } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, access, type FileHandle } from "node:fs/promises";
import path from "node:path";
import type { Stats } from "node:fs";
import { getNodeValue, parseTree, type Node, type ParseError } from "jsonc-parser";
export type FileState = "present" | "missing" | "unreadable" | "symlink-skipped" | "not-file" | "too-large" | "malformed";
const MAX_CONFIG_BYTES = 1024 * 1024;
const object = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const code = (error: unknown): string | undefined => (error as NodeJS.ErrnoException)?.code;
const missing = (error: unknown) => code(error) === "ENOENT";

/** Reject every symlink component, including dangling links, before opening a fixed candidate. */
export async function inspect(file: string): Promise<FileState> {
  try {
    const parsed = path.parse(file);
    let current = parsed.root;
    const components = file.slice(parsed.root.length).split(path.sep).filter(Boolean);
    for (let i = 0; i < components.length; i++) {
      current = path.join(current, components[i]);
      const stat = await lstat(current);
      if (stat.isSymbolicLink()) return "symlink-skipped";
      if (i < components.length - 1 && !stat.isDirectory()) return "not-file";
      if (i === components.length - 1 && !stat.isFile()) return "not-file";
    }
    await access(file, constants.R_OK);
    return "present";
  } catch (error) {
    return missing(error) ? "missing" : "unreadable";
  }
}

function duplicateKeys(node: Node): boolean {
  if (node.type === "object") {
    const names = node.children?.map(property => property.children?.[0].value) ?? [];
    if (new Set(names).size !== names.length) return true;
  }
  return node.children?.some(duplicateKeys) ?? false;
}

export const fileIdentity = (stat: Stats): string => [stat.dev, stat.ino, stat.mode, stat.size, stat.mtimeMs, stat.ctimeMs].join(":");

/** One explicit file only. This is not a contained recursive directory reader. */
export async function readBoundedBytes(file: string, maxBytes = MAX_CONFIG_BYTES, retainHandle = false): Promise<{ state: FileState; bytes?: Buffer; identity?: string; handle?: FileHandle }> {
  const state = await inspect(file);
  if (state !== "present") return { state };
  try {
    const before = await lstat(file);
    // Do not follow a final symlink or block if a regular file was replaced by a FIFO.
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    let retained = false;
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) return { state: "not-file" };
      if (fileIdentity(stat) !== fileIdentity(before)) return { state: "unreadable" };
      if (stat.size > maxBytes) return { state: "too-large" };
      const buffer = Buffer.alloc(maxBytes + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > maxBytes) return { state: "too-large" };
      const after = await handle.stat();
      const named = await lstat(file);
      if (fileIdentity(after) !== fileIdentity(stat) || fileIdentity(named) !== fileIdentity(stat) || named.isSymbolicLink()) return { state: "unreadable" };
      const bytes = buffer.subarray(0, length);
      retained = retainHandle;
      return { state: "present", bytes, identity: fileIdentity(stat), ...(retained ? { handle } : {}) };
    } finally { if (!retained) await handle.close(); }
  } catch (error) {
    return { state: code(error) === "ELOOP" ? "symlink-skipped" : "unreadable" };
  }
}

/** Parse exactly the retained bytes, rejecting duplicate keys and invalid UTF-8. */
export function parseJsonObject(bytes: Buffer, options: { jsonc?: boolean } = {}): Record<string, unknown> | undefined {
  try {
    if (!isUtf8(bytes)) return undefined;
    const text = bytes.toString("utf8");
    const raw = options.jsonc ? text.replace(/^\uFEFF/, "") : text;
    const errors: ParseError[] = [];
    const tree = parseTree(raw, errors, { disallowComments: !options.jsonc, allowTrailingComma: options.jsonc === true });
    if (!tree || errors.length || duplicateKeys(tree)) return undefined;
    const value: unknown = options.jsonc ? getNodeValue(tree) : JSON.parse(raw);
    return object(value) ? value : undefined;
  } catch { return undefined; }
}

export async function readConfig(file: string, options: { allowEmpty?: boolean; jsonc?: boolean } = {}): Promise<{ state: FileState; value?: Record<string, unknown> }> {
  const result = await readBoundedBytes(file);
  if (!result.bytes) return { state: result.state };
  if (options.allowEmpty && isUtf8(result.bytes) && result.bytes.toString("utf8").trim() === "") return { state: "present", value: {} };
  const value = parseJsonObject(result.bytes, options);
  return value ? { state: "present", value } : { state: "malformed" };
}

