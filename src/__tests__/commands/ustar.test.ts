import { expect, it } from "vitest";
import { parseUstar, MAX_MEMBER_BYTES } from "../../artifacts/ustar.js";
import { ustar } from "./ustar-fixture.js";

function checksum(bytes: Buffer): Buffer {
  bytes.fill(32, 148, 156);
  bytes.write(bytes.subarray(0, 512).reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, "0") + "\0 ", 148, 8);
  return bytes;
}
it("reads POSIX name/prefix, binary payload and executable mode from retained bytes", () => {
  const input = ustar([{ name: "file.bin", prefix: "nested", body: Buffer.from([255]), mode: 0o755 }]);
  const result = parseUstar(input);
  expect(result.error).toBeUndefined();
  expect(result.members).toEqual([{ path: "nested/file.bin", mode: 0o755, bytes: Buffer.from([255]) }]);
  input[512] = 42;
  expect(result.members[0].bytes[0]).toBe(42);
});
it.each(["../escape", "/absolute", "a/../../escape", "C:/absolute", "a\\escape", "a//b", "a/./b", "a/../b", "a\nsecret"])("rejects unsafe member path %s", name => {
  expect(parseUstar(ustar([{ name }])).error).toBe("outside-root");
});
it.each(["1", "2", "3", "4", "6", "7", "x", "g", "L", "S"])("rejects unsupported record %s without returning partial inventory", type => {
  expect(parseUstar(ustar([{ name: "valid", body: "x" }, { name: "unsupported", type }]))).toEqual({ members: [], error: "unsupported-record" });
});
it("rejects checksum, number, magic, version, padding, truncation and trailing archive errors", () => {
  const input = ustar([{ name: "file", body: "x" }]);
  const wrongChecksum = Buffer.from(input); wrongChecksum[0] ^= 1;
  expect(parseUstar(wrongChecksum).error).toBe("checksum-mismatch");
  const wrongNumber = Buffer.from(input); wrongNumber[124] = 128;
  expect(parseUstar(checksum(wrongNumber)).error).toBe("invalid-number");
  const wrongSize = Buffer.from(input); wrongSize.write("77777777777\0", 124, 12);
  expect(parseUstar(checksum(wrongSize)).error).toBe("member-too-large");
  for (const offset of [257, 263, 500]) { const invalid = Buffer.from(input); invalid[offset] = 33; expect(parseUstar(checksum(invalid)).error).toBe("unsupported-header"); }
  for (const offset of [257, 262, 263]) { const invalid = Buffer.from(input); invalid[offset] |= 128; expect(parseUstar(checksum(invalid)).error).toBe("unsupported-header"); }
  const padding = Buffer.from(input); padding[513] = 1;
  expect(parseUstar(padding).error).toBe("nonzero-padding");
  expect(parseUstar(input.subarray(0, input.length - 1)).error).toBe("truncated-archive");
  expect(parseUstar(input.subarray(0, 512)).error).toBe("truncated-archive");
  expect(parseUstar(input.subarray(0, 1024)).error).toBe("missing-end-marker");
  expect(parseUstar(input.subarray(0, 1536)).error).toBe("invalid-end-marker");
  expect(parseUstar(Buffer.concat([input, input])).error).toBe("invalid-end-marker");
  const pastEnd = Buffer.from(input); pastEnd[pastEnd.length - 1] = 1;
  expect(parseUstar(pastEnd).error).toBe("invalid-end-marker");
});
it("rejects duplicate normalized names and file/directory ancestor conflicts in either order", () => {
  expect(parseUstar(ustar([{ name: "a" }, { name: "./a" }])).error).toBe("duplicate-member");
  for (const entries of [[{ name: "a" }, { name: "a/b" }], [{ name: "a/b" }, { name: "a" }]]) expect(parseUstar(ustar(entries)).error).toBe("member-type-conflict");
  expect(parseUstar(ustar([{ name: "a", type: "5" }, { name: "a" }])).error).toBe("duplicate-member");
});
it("enforces fixed member, entry, depth and byte limits", () => {
  expect(parseUstar(ustar([{ name: "large", body: Buffer.alloc(MAX_MEMBER_BYTES + 1) }])).error).toBe("member-too-large");
  expect(parseUstar(ustar(Array.from({ length: 257 }, (_, i) => ({ name: "file" + i })))).error).toBe("too-many-members");
  expect(parseUstar(ustar(Array.from({ length: 513 }, (_, i) => ({ name: "dir" + i, type: "5" })))).error).toBe("too-many-members");
  expect(parseUstar(ustar([{ name: Array(17).fill("a").join("/") }])).error).toBe("outside-root");
  expect(parseUstar(Buffer.alloc(16 * 1024 * 1024 + 512)).error).toBe("archive-too-large");
});

it("rejects high-bit aliases in every numeric field and the type flag", () => {
  const input = ustar([{ name: "file", body: "x" }]);
  for (const offset of [100, 108, 116, 124, 136, 329, 337]) {
    const invalid = Buffer.from(input); invalid[offset] |= 128;
    expect(parseUstar(checksum(invalid)).error).toBe("invalid-number");
  }
  const invalidChecksum = Buffer.from(input); invalidChecksum[148] |= 128;
  expect(parseUstar(invalidChecksum).error).toBe("invalid-number");
  const invalidType = Buffer.from(input); invalidType[156] |= 128;
  expect(parseUstar(checksum(invalidType)).error).toBe("unsupported-record");
});
