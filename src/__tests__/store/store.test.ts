/**
 * Tests for src/store/index.ts
 *
 * TDD — RED phase.
 * Mocks fs/promises and os.homedir — no real filesystem.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("os")>();
  return { ...actual, default: { ...actual, homedir: vi.fn(() => "/home/alice") } };
});

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
}));

import os from "os";
import { readFile, writeFile, rename, mkdir } from "fs/promises";
import {
  getStorePath,
  readJson,
  writeJson,
  _resetCachedStorePath,
} from "../../store/index.js";

const mockHomedir = os.homedir as ReturnType<typeof vi.fn>;
const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockWriteFile = writeFile as ReturnType<typeof vi.fn>;
const mockRename = rename as ReturnType<typeof vi.fn>;
const mockMkdir = mkdir as ReturnType<typeof vi.fn>;

describe("getStorePath", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    _resetCachedStorePath();
    mockMkdir.mockResolvedValue(undefined);
  });

  it("returns ~/.mcpm/ path", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const storePath = await getStorePath();
    expect(storePath).toBe("/home/alice/.mcpm");
  });

  it("creates the directory if it does not exist", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await getStorePath();
    expect(mockMkdir).toHaveBeenCalledWith("/home/alice/.mcpm", {
      recursive: true,
      mode: 0o700,
    });
  });

  it("returns path even when mkdir throws (already exists is fine)", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    // mkdir throws EEXIST — should be swallowed
    const err = Object.assign(new Error("EEXIST"), { code: "EEXIST" });
    mockMkdir.mockRejectedValue(err);
    // Should NOT throw
    const storePath = await getStorePath();
    expect(storePath).toBe("/home/alice/.mcpm");
  });
});

describe("readJson", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockMkdir.mockResolvedValue(undefined);
  });

  it("returns parsed JSON when file exists", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const data = { foo: "bar", count: 42 };
    mockReadFile.mockResolvedValue(JSON.stringify(data));
    const result = await readJson<typeof data>("data.json");
    expect(result).toEqual(data);
  });

  it("returns null when file does not exist (ENOENT)", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const err = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockReadFile.mockRejectedValue(err);
    const result = await readJson("missing.json");
    expect(result).toBeNull();
  });

  it("throws on malformed JSON", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    mockReadFile.mockResolvedValue("{ not valid json ]");
    await expect(readJson("bad.json")).rejects.toThrow();
  });

  it("throws on permission denied (EACCES)", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const err = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockReadFile.mockRejectedValue(err);
    await expect(readJson("secret.json")).rejects.toThrow();
  });

  it("reads from correct path under ~/.mcpm/", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    mockReadFile.mockResolvedValue(JSON.stringify({}));
    await readJson("myfile.json");
    expect(mockReadFile).toHaveBeenCalledWith(
      "/home/alice/.mcpm/myfile.json",
      "utf-8"
    );
  });
});

describe("writeJson", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    _resetCachedStorePath();
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("writes data as formatted JSON", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const data = { items: [1, 2, 3] };
    await writeJson("output.json", data);

    expect(mockWriteFile).toHaveBeenCalledOnce();
    const writtenStr = mockWriteFile.mock.calls[0][1] as string;
    expect(JSON.parse(writtenStr)).toEqual(data);
  });

  it("uses atomic write: writes to .tmp then renames", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await writeJson("data.json", { x: 1 });

    expect(mockRename).toHaveBeenCalledOnce();
    const [tmpPath, finalPath] = mockRename.mock.calls[0] as [string, string];
    expect(tmpPath).toMatch(/\.tmp$/);
    expect(finalPath).toBe("/home/alice/.mcpm/data.json");
  });

  it("creates store directory before writing", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await writeJson("data.json", {});
    expect(mockMkdir).toHaveBeenCalledWith("/home/alice/.mcpm", {
      recursive: true,
      mode: 0o700,
    });
  });

  it("does not mutate the data passed in", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    const data = { key: "value" };
    const copy = { ...data };
    await writeJson("x.json", data);
    expect(data).toEqual(copy);
  });
});

describe("readJson — path traversal protection", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockMkdir.mockResolvedValue(undefined);
  });

  it("throws when filename traverses outside the store directory", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await expect(readJson("../../etc/passwd")).rejects.toThrow(/path traversal/i);
  });

  it("throws for absolute path that escapes store", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await expect(readJson("../sibling/file.json")).rejects.toThrow(/path traversal/i);
  });

  it("allows normal relative filenames within the store", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    mockReadFile.mockResolvedValue(JSON.stringify({}));
    await expect(readJson("servers.json")).resolves.not.toThrow();
  });
});

describe("writeJson — path traversal protection", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockRename.mockResolvedValue(undefined);
  });

  it("throws when filename traverses outside the store directory", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await expect(writeJson("../../etc/crontab", {})).rejects.toThrow(/path traversal/i);
  });

  it("allows normal relative filenames within the store", async () => {
    mockHomedir.mockReturnValue("/home/alice");
    await expect(writeJson("servers.json", {})).resolves.not.toThrow();
  });
});
