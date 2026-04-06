/**
 * Tests for src/config/paths.ts
 *
 * TDD — RED phase. All tests written before implementation.
 * Mocks process.platform and os.homedir for cross-platform coverage.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// We use vi.mock for os so we can control homedir in every test.
vi.mock("os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("os")>();
  return { ...actual, default: { ...actual, homedir: vi.fn() } };
});

import os from "os";
import { getConfigPath } from "../../config/paths.js";
import type { ClientId } from "../../config/paths.js";

const mockHomedir = os.homedir as ReturnType<typeof vi.fn>;

describe("getConfigPath", () => {
  const originalPlatform = process.platform;

  afterEach(() => {
    vi.resetAllMocks();
    Object.defineProperty(process, "platform", { value: originalPlatform });
  });

  function setPlatform(platform: string) {
    Object.defineProperty(process, "platform", {
      value: platform,
      writable: true,
    });
  }

  // -------------------------------------------------------------------------
  // Claude Desktop
  // -------------------------------------------------------------------------

  describe("claude-desktop", () => {
    it("returns macOS path on darwin", () => {
      setPlatform("darwin");
      mockHomedir.mockReturnValue("/Users/alice");
      const result = getConfigPath("claude-desktop");
      expect(result).toBe(
        "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json"
      );
    });

    it("returns Linux path on linux", () => {
      setPlatform("linux");
      mockHomedir.mockReturnValue("/home/alice");
      const result = getConfigPath("claude-desktop");
      expect(result).toBe(
        "/home/alice/.config/Claude/claude_desktop_config.json"
      );
    });

    it("returns Windows path on win32", () => {
      setPlatform("win32");
      mockHomedir.mockReturnValue("C:\\Users\\alice");
      // APPDATA env var is used on Windows
      process.env["APPDATA"] = "C:\\Users\\alice\\AppData\\Roaming";
      const result = getConfigPath("claude-desktop");
      expect(result).toBe(
        "C:\\Users\\alice\\AppData\\Roaming/Claude/claude_desktop_config.json"
      );
      delete process.env["APPDATA"];
    });

    it("falls back to homedir when APPDATA is not set on win32", () => {
      setPlatform("win32");
      mockHomedir.mockReturnValue("C:\\Users\\alice");
      const savedAppData = process.env["APPDATA"];
      delete process.env["APPDATA"];
      const result = getConfigPath("claude-desktop");
      expect(result).toContain("claude_desktop_config.json");
      if (savedAppData !== undefined) {
        process.env["APPDATA"] = savedAppData;
      }
    });
  });

  // -------------------------------------------------------------------------
  // Cursor
  // -------------------------------------------------------------------------

  describe("cursor", () => {
    it("returns ~/.cursor/mcp.json on darwin", () => {
      setPlatform("darwin");
      mockHomedir.mockReturnValue("/Users/alice");
      const result = getConfigPath("cursor");
      expect(result).toBe("/Users/alice/.cursor/mcp.json");
    });

    it("returns ~/.cursor/mcp.json on linux", () => {
      setPlatform("linux");
      mockHomedir.mockReturnValue("/home/alice");
      const result = getConfigPath("cursor");
      expect(result).toBe("/home/alice/.cursor/mcp.json");
    });

    it("returns home-relative path on win32 (NOT APPDATA)", () => {
      setPlatform("win32");
      mockHomedir.mockReturnValue("C:\\Users\\alice");
      process.env["APPDATA"] = "C:\\Users\\alice\\AppData\\Roaming";
      const result = getConfigPath("cursor");
      // path.join separator is platform-specific; assert content not APPDATA
      expect(result).toContain(".cursor");
      expect(result).toContain("mcp.json");
      expect(result).not.toContain("AppData");
      delete process.env["APPDATA"];
    });
  });

  // -------------------------------------------------------------------------
  // VS Code
  // -------------------------------------------------------------------------

  describe("vscode", () => {
    it("returns macOS path on darwin", () => {
      setPlatform("darwin");
      mockHomedir.mockReturnValue("/Users/alice");
      const result = getConfigPath("vscode");
      expect(result).toBe(
        "/Users/alice/Library/Application Support/Code/User/mcp.json"
      );
    });

    it("returns Linux path on linux", () => {
      setPlatform("linux");
      mockHomedir.mockReturnValue("/home/alice");
      const result = getConfigPath("vscode");
      expect(result).toBe("/home/alice/.config/Code/User/mcp.json");
    });

    it("returns Windows path on win32", () => {
      setPlatform("win32");
      mockHomedir.mockReturnValue("C:\\Users\\alice");
      process.env["APPDATA"] = "C:\\Users\\alice\\AppData\\Roaming";
      const result = getConfigPath("vscode");
      expect(result).toBe(
        "C:\\Users\\alice\\AppData\\Roaming/Code/User/mcp.json"
      );
      delete process.env["APPDATA"];
    });
  });

  // -------------------------------------------------------------------------
  // Windsurf
  // -------------------------------------------------------------------------

  describe("windsurf", () => {
    it("returns ~/.codeium/windsurf/mcp_config.json on darwin", () => {
      setPlatform("darwin");
      mockHomedir.mockReturnValue("/Users/alice");
      const result = getConfigPath("windsurf");
      expect(result).toBe(
        "/Users/alice/.codeium/windsurf/mcp_config.json"
      );
    });

    it("returns ~/.codeium/windsurf/mcp_config.json on linux", () => {
      setPlatform("linux");
      mockHomedir.mockReturnValue("/home/alice");
      const result = getConfigPath("windsurf");
      expect(result).toBe(
        "/home/alice/.codeium/windsurf/mcp_config.json"
      );
    });

    it("returns home-relative path on win32 (NOT APPDATA)", () => {
      setPlatform("win32");
      mockHomedir.mockReturnValue("C:\\Users\\alice");
      process.env["APPDATA"] = "C:\\Users\\alice\\AppData\\Roaming";
      const result = getConfigPath("windsurf");
      // path.join separator is platform-specific; assert content not APPDATA
      expect(result).toContain(".codeium");
      expect(result).toContain("windsurf");
      expect(result).toContain("mcp_config.json");
      expect(result).not.toContain("AppData");
      delete process.env["APPDATA"];
    });
  });

  // -------------------------------------------------------------------------
  // Platform override parameter
  // -------------------------------------------------------------------------

  it("accepts an explicit platform override", () => {
    mockHomedir.mockReturnValue("/Users/alice");
    const result = getConfigPath("claude-desktop", "linux");
    expect(result).toBe(
      "/Users/alice/.config/Claude/claude_desktop_config.json"
    );
  });

  it("throws for an unknown clientId", () => {
    setPlatform("darwin");
    mockHomedir.mockReturnValue("/Users/alice");
    expect(() =>
      getConfigPath("unknown-client" as ClientId)
    ).toThrow();
  });
});
