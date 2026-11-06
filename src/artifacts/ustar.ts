/** Strict, uncompressed USTAR00 subset. Member names never reach the filesystem. */
import { isUtf8 } from "node:buffer";

export const MAX_ARCHIVE_BYTES = 16 * 1024 * 1024;
export const MAX_MEMBER_BYTES = 2 * 1024 * 1024;
export interface ArchiveMember { path: string; bytes: Buffer; mode: number; }
export interface ArchiveResult { members: ArchiveMember[]; directories?: string[]; error?: string; }
const zero = (bytes: Buffer) => bytes.every(byte => byte === 0);

/** Canonical portable relative path, shared by archive names and resource references. */
export function memberPath(value: string): string | undefined {
  if (!value || value.startsWith("/") || /^[a-z]:/i.test(value) || /[\\\x00-\x1f\x7f]/.test(value)) return undefined;
  const normalized = value.replace(/^(\.\/)+/, "").replace(/\/$/, "");
  const parts = normalized.split("/");
  return parts.length <= 16 && parts.every(part => part && part !== "." && part !== "..") ? normalized : undefined;
}

function text(bytes: Buffer): string {
  const end = bytes.indexOf(0);
  if (end >= 0 && !zero(bytes.subarray(end))) throw new Error("invalid-header");
  const field = end < 0 ? bytes : bytes.subarray(0, end);
  if (!isUtf8(field)) throw new Error("invalid-header");
  return field.toString("utf8");
}
function octal(bytes: Buffer, empty = false): number {
  if (bytes.some(byte => byte > 127)) throw new Error("invalid-number");
  const raw = bytes.toString("ascii").replace(/[\x00 ]+$/, "").replace(/^ +/, "");
  if (empty && !raw) return 0;
  if (!/^[0-7]+$/.test(raw)) throw new Error("invalid-number");
  const result = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(result)) throw new Error("invalid-number");
  return result;
}

export function parseUstar(bytes: Buffer): ArchiveResult {
  try {
    if (bytes.length > MAX_ARCHIVE_BYTES) throw new Error("archive-too-large");
    if (bytes.length < 1024 || bytes.length % 512) throw new Error("truncated-archive");
    const members: ArchiveMember[] = [];
    const names = new Map<string, "file" | "directory">();
    for (let offset = 0; offset + 512 <= bytes.length;) {
      const header = bytes.subarray(offset, offset + 512);
      if (zero(header)) {
        if (offset + 1024 > bytes.length || !zero(bytes.subarray(offset))) throw new Error("invalid-end-marker");
        // An invalid or unsupported archive never returns a partial definitive inventory.
        return { members, directories: [...names].filter(([, kind]) => kind === "directory").map(([name]) => name) };
      }
      if (!header.subarray(257, 265).equals(Buffer.from("ustar\x0000")) || !zero(header.subarray(500))) throw new Error("unsupported-header");
      const expected = octal(header.subarray(148, 156));
      const checksum = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
      if (checksum !== expected) throw new Error("checksum-mismatch");
      const name = text(header.subarray(0, 100));
      const prefix = text(header.subarray(345, 500));
      const target = memberPath(prefix ? `${prefix}/${name}` : name);
      if (!target) throw new Error("outside-root");
      const type = header[156];
      if (type !== 0 && type !== 48 && type !== 53) throw new Error("unsupported-record");
      if (type !== 53 && name.endsWith("/")) throw new Error("invalid-header");
      if (text(header.subarray(157, 257)) !== "" || octal(header.subarray(329, 337), true) || octal(header.subarray(337, 345), true)) throw new Error("unsupported-header");
      const mode = octal(header.subarray(100, 108));
      if (mode > 0o7777) throw new Error("unsupported-mode");
      octal(header.subarray(108, 116)); octal(header.subarray(116, 124)); octal(header.subarray(136, 148));
      const size = octal(header.subarray(124, 136));
      if (size > MAX_MEMBER_BYTES) throw new Error("member-too-large");
      if (type === 53 && size !== 0) throw new Error("invalid-directory");
      if (names.has(target)) throw new Error("duplicate-member");
      if (names.size >= 512 || (type !== 53 && members.length >= 256)) throw new Error("too-many-members");
      names.set(target, type === 53 ? "directory" : "file");
      const start = offset + 512;
      const next = start + Math.ceil(size / 512) * 512;
      if (next > bytes.length) throw new Error("truncated-archive");
      if (!zero(bytes.subarray(start + size, next))) throw new Error("nonzero-padding");
      if (type !== 53) members.push({ path: target, mode, bytes: bytes.subarray(start, start + size) });
      for (const name of names.keys()) {
        const segments = name.split("/");
        for (let i = 1; i < segments.length; i++) if (names.get(segments.slice(0, i).join("/")) === "file") throw new Error("member-type-conflict");
      }
      offset = next;
    }
    throw new Error("missing-end-marker");
  } catch (error) {
    return { members: [], error: error instanceof Error ? error.message : "invalid-archive" };
  }
}
