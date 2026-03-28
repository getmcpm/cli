/**
 * Tests for src/config/detector.ts
 *
 * TDD — RED phase.
 * Mocks fs.access so no real filesystem is touched.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("os", () => ({ homedir: vi.fn(() => "/home/alice") }));

vi.mock("fs/promises", () => ({
  access: vi.fn(),
}));

// paths.ts also imports os — the mock above covers it.
vi.mock("../../config/paths.js", () => ({
  getConfigPath: vi.fn((clientId: string) => `/fake/${clientId}/config.json`),
  CLIENT_IDS: ["claude-desktop", "cursor", "vscode", "windsurf"],
}));

import { access } from "fs/promises";
import { detectInstalledClients } from "../../config/detector.js";

const mockAccess = access as ReturnType<typeof vi.fn>;

describe("detectInstalledClients", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns all clients when all config files exist", async () => {
    mockAccess.mockResolvedValue(undefined);
    const result = await detectInstalledClients();
    expect(result).toEqual(["claude-desktop", "cursor", "vscode", "windsurf"]);
  });

  it("returns empty array when no config files exist", async () => {
    mockAccess.mockRejectedValue(new Error("ENOENT"));
    const result = await detectInstalledClients();
    expect(result).toEqual([]);
  });

  it("returns only clients whose config files exist", async () => {
    // claude-desktop exists, others do not
    mockAccess.mockImplementation((filePath: string) => {
      if (filePath.includes("claude-desktop")) {
        return Promise.resolve(undefined);
      }
      return Promise.reject(new Error("ENOENT"));
    });
    const result = await detectInstalledClients();
    expect(result).toEqual(["claude-desktop"]);
  });

  it("handles mixed success/failure gracefully", async () => {
    let callCount = 0;
    mockAccess.mockImplementation(() => {
      callCount++;
      // cursor (2nd call) and windsurf (4th call) exist
      if (callCount === 2 || callCount === 4) {
        return Promise.resolve(undefined);
      }
      return Promise.reject(new Error("ENOENT"));
    });
    const result = await detectInstalledClients();
    expect(result).toEqual(["cursor", "windsurf"]);
  });

  it("returns a new array each call (immutable result)", async () => {
    mockAccess.mockResolvedValue(undefined);
    const first = await detectInstalledClients();
    const second = await detectInstalledClients();
    expect(first).not.toBe(second);
    expect(first).toEqual(second);
  });

  it("handles EACCES (permission denied) as not-installed", async () => {
    const err = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockAccess.mockRejectedValue(err);
    const result = await detectInstalledClients();
    expect(result).toEqual([]);
  });
});
