/**
 * Tests for src/store/servers.ts
 *
 * TDD — RED phase.
 * Mocks the store/index.js module entirely.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("../../store/index.js", () => ({
  getStorePath: vi.fn(async () => "/home/alice/.mcpm"),
  readJson: vi.fn(),
  writeJson: vi.fn(),
}));

import { readJson, writeJson } from "../../store/index.js";
import {
  getInstalledServers,
  addInstalledServer,
  removeInstalledServer,
} from "../../store/servers.js";
import type { InstalledServer } from "../../store/servers.js";

const mockReadJson = readJson as ReturnType<typeof vi.fn>;
const mockWriteJson = writeJson as ReturnType<typeof vi.fn>;

const SAMPLE_SERVER: InstalledServer = {
  name: "my-mcp-server",
  version: "1.0.0",
  clients: ["claude-desktop", "cursor"],
  installedAt: "2026-03-28T00:00:00.000Z",
};

describe("getInstalledServers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteJson.mockResolvedValue(undefined);
  });

  it("returns empty array when no file exists", async () => {
    mockReadJson.mockResolvedValue(null);
    const result = await getInstalledServers();
    expect(result).toEqual([]);
  });

  it("returns persisted server list", async () => {
    mockReadJson.mockResolvedValue([SAMPLE_SERVER]);
    const result = await getInstalledServers();
    expect(result).toEqual([SAMPLE_SERVER]);
  });

  it("returns a new array each call (not the cached reference)", async () => {
    mockReadJson.mockResolvedValue([SAMPLE_SERVER]);
    const first = await getInstalledServers();
    const second = await getInstalledServers();
    expect(first).not.toBe(second);
  });

  it("reads from the correct filename", async () => {
    mockReadJson.mockResolvedValue(null);
    await getInstalledServers();
    expect(mockReadJson).toHaveBeenCalledWith("servers.json");
  });
});

describe("addInstalledServer", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteJson.mockResolvedValue(undefined);
  });

  it("appends a server to the list", async () => {
    mockReadJson.mockResolvedValue([]);
    await addInstalledServer(SAMPLE_SERVER);
    expect(mockWriteJson).toHaveBeenCalledOnce();
    const [filename, data] = mockWriteJson.mock.calls[0] as [
      string,
      InstalledServer[],
    ];
    expect(filename).toBe("servers.json");
    expect(data).toContainEqual(SAMPLE_SERVER);
  });

  it("preserves existing servers when adding new", async () => {
    const existing: InstalledServer = {
      name: "existing-srv",
      version: "0.1.0",
      clients: ["vscode"],
      installedAt: "2026-01-01T00:00:00.000Z",
    };
    mockReadJson.mockResolvedValue([existing]);
    await addInstalledServer(SAMPLE_SERVER);
    const [, data] = mockWriteJson.mock.calls[0] as [string, InstalledServer[]];
    expect(data).toHaveLength(2);
    expect(data).toContainEqual(existing);
    expect(data).toContainEqual(SAMPLE_SERVER);
  });

  it("does not mutate the server object passed in", async () => {
    mockReadJson.mockResolvedValue([]);
    const srv = { ...SAMPLE_SERVER };
    const srvcopy = { ...srv };
    await addInstalledServer(srv);
    expect(srv).toEqual(srvcopy);
  });

  it("handles null file (first install) by starting fresh", async () => {
    mockReadJson.mockResolvedValue(null);
    await addInstalledServer(SAMPLE_SERVER);
    const [, data] = mockWriteJson.mock.calls[0] as [string, InstalledServer[]];
    expect(data).toEqual([SAMPLE_SERVER]);
  });
});

describe("removeInstalledServer", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockWriteJson.mockResolvedValue(undefined);
  });

  it("removes the named server from the list", async () => {
    const other: InstalledServer = {
      name: "other-srv",
      version: "2.0.0",
      clients: ["windsurf"],
      installedAt: "2026-02-01T00:00:00.000Z",
    };
    mockReadJson.mockResolvedValue([SAMPLE_SERVER, other]);
    await removeInstalledServer("my-mcp-server");
    const [, data] = mockWriteJson.mock.calls[0] as [string, InstalledServer[]];
    expect(data).not.toContainEqual(SAMPLE_SERVER);
    expect(data).toContainEqual(other);
  });

  it("throws if the server is not found", async () => {
    mockReadJson.mockResolvedValue([SAMPLE_SERVER]);
    await expect(removeInstalledServer("ghost")).rejects.toThrow(/not found/i);
  });

  it("writes the updated list (not original reference)", async () => {
    mockReadJson.mockResolvedValue([SAMPLE_SERVER]);
    await removeInstalledServer("my-mcp-server");
    const [, data] = mockWriteJson.mock.calls[0] as [string, InstalledServer[]];
    expect(data).toEqual([]);
  });

  it("handles empty list and throws", async () => {
    mockReadJson.mockResolvedValue([]);
    await expect(removeInstalledServer("any")).rejects.toThrow(/not found/i);
  });
});
