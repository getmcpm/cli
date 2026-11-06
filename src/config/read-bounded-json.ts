/** Bounded, strict JSON snapshot reader shared by non-executing configuration checks. */
import { isUtf8 } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, access } from "node:fs/promises";
import path from "node:path";
import { parseTree, type Node, type ParseError } from "jsonc-parser";
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

export async function readConfig(file: string, options: { allowEmpty?: boolean } = {}): Promise<{ state: FileState; value?: Record<string, unknown> }> {
  const state = await inspect(file);
  if (state !== "present") return { state };
  try {
    // Do not follow a final symlink or block if a regular file was replaced by a FIFO.
    const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
    try {
      const stat = await handle.stat();
      if (!stat.isFile()) return { state: "not-file" };
      if (stat.size > MAX_CONFIG_BYTES) return { state: "too-large" };
      const buffer = Buffer.alloc(MAX_CONFIG_BYTES + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length > MAX_CONFIG_BYTES) return { state: "too-large" };
      const after = await handle.stat();
      const named = await lstat(file);
      if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size ||
          after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs ||
          named.dev !== stat.dev || named.ino !== stat.ino || named.isSymbolicLink()) return { state: "unreadable" };
      const bytes = buffer.subarray(0, length);
      if (!isUtf8(bytes)) return { state: "malformed" };
      const raw = bytes.toString("utf8");
      if (options.allowEmpty && raw.trim() === "") return { state: "present", value: {} };
      const errors: ParseError[] = [];
      const tree = parseTree(raw, errors, { disallowComments: true, allowTrailingComma: false });
      if (!tree || errors.length || duplicateKeys(tree)) return { state: "malformed" };
      const value: unknown = JSON.parse(raw);
      return object(value) ? { state: "present", value } : { state: "malformed" };
    } finally { await handle.close(); }
  } catch (error) {
    return { state: code(error) === "ELOOP" ? "symlink-skipped" : "unreadable" };
  }
}

