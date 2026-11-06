/** Test-only POSIX USTAR writer; production never creates or extracts archives. */
export function ustar(entries: { name: string; body?: string | Buffer; type?: string; mode?: number; prefix?: string }[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const body = Buffer.isBuffer(entry.body) ? entry.body : Buffer.from(entry.body ?? "");
    const header = Buffer.alloc(512);
    header.write(entry.name, 0, 100);
    for (const [offset, width, value] of [[100, 8, entry.mode ?? 0o644], [108, 8, 0], [116, 8, 0], [124, 12, body.length], [136, 12, 0]] as const) header.write(value.toString(8).padStart(width - 1, "0") + "\0", offset, width);
    header.fill(32, 148, 156); header.write(entry.type ?? "0", 156); header.write("ustar\x0000", 257); header.write(entry.prefix ?? "", 345, 155);
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, "0") + "\0 ", 148, 8);
    parts.push(header, body, Buffer.alloc((512 - body.length % 512) % 512));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}
