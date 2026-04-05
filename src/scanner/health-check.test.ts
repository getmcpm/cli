/**
 * Tests for src/scanner/health-check.ts
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { EventEmitter } from "node:events";
import { Readable, Writable } from "node:stream";
import { runHealthCheck } from "./health-check.js";
import type { McpServerEntry } from "../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Mock child_process.spawn
// ---------------------------------------------------------------------------

vi.mock("node:child_process", () => ({
  spawn: vi.fn(),
}));

import { spawn } from "node:child_process";
const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

function createMockChild(stdout: string, _exitCode = 0, error?: Error) {
  const stdoutEmitter = new EventEmitter();
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    stdin: { write: ReturnType<typeof vi.fn>; end: ReturnType<typeof vi.fn> };
    kill: ReturnType<typeof vi.fn>;
  };
  child.stdout = stdoutEmitter;
  child.stderr = new EventEmitter();
  child.stdin = { write: vi.fn(), end: vi.fn() };
  child.kill = vi.fn();

  // Emit events on next tick so listeners are attached first
  setTimeout(() => {
    if (error) {
      child.emit("error", error);
      return;
    }
    if (stdout) {
      child.stdout.emit("data", Buffer.from(stdout));
    }
    child.emit("close", _exitCode);
  }, 5);

  return child;
}

describe("runHealthCheck", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  // -------------------------------------------------------------------------
  // Tier 1: HTTP/URL entries
  // -------------------------------------------------------------------------

  it("returns tier 1 pass for URL-based entries", async () => {
    const entry: McpServerEntry = { url: "https://example.com/mcp" };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(1);
    expect(result.passed).toBe(true);
    expect(result.toolCount).toBeNull();
  });

  it("returns tier 1 fail for entries with no command or URL", async () => {
    const entry = {} as McpServerEntry;
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(1);
    expect(result.passed).toBe(false);
    expect(result.error).toContain("No command or URL");
  });

  // -------------------------------------------------------------------------
  // Tier 2: Process start
  // -------------------------------------------------------------------------

  it("returns tier 2 fail when process returns empty output", async () => {
    mockSpawn.mockReturnValue(createMockChild(""));
    const entry: McpServerEntry = { command: "npx", args: ["-y", "test-server"] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(2);
    expect(result.passed).toBe(false);
    expect(result.error).toContain("no output");
  });

  it("returns tier 2 fail when command is not in allowlist", async () => {
    const entry: McpServerEntry = { command: "nonexistent", args: [] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(2);
    expect(result.passed).toBe(false);
    expect(result.error).toContain("not in health-check allowlist");
  });

  it("returns tier 2 fail when allowed process emits error", async () => {
    mockSpawn.mockReturnValue(createMockChild("", 1, new Error("ENOENT: command not found")));
    const entry: McpServerEntry = { command: "npx", args: ["-y", "nonexistent-server"] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(2);
    expect(result.passed).toBe(false);
    expect(result.error).toContain("Failed to start");
  });

  it("returns tier 2 pass when server responds to initialize but not tools/list", async () => {
    const initResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "test", version: "1.0" } },
    });
    mockSpawn.mockReturnValue(createMockChild(initResponse));

    const entry: McpServerEntry = { command: "npx", args: ["-y", "test-server"] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(2);
    expect(result.passed).toBe(true);
    expect(result.toolCount).toBeNull();
    expect(result.error).toContain("not tools/list");
  });

  // -------------------------------------------------------------------------
  // Tier 3: Tool listing
  // -------------------------------------------------------------------------

  it("returns tier 3 pass with tool count when tools/list succeeds", async () => {
    const initResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      result: { protocolVersion: "2025-03-26", capabilities: {} },
    });
    const toolsResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "tool_a" }, { name: "tool_b" }, { name: "tool_c" }] },
    });
    mockSpawn.mockReturnValue(createMockChild(`${initResponse}\n${toolsResponse}`));

    const entry: McpServerEntry = { command: "npx", args: ["-y", "test-server"] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(3);
    expect(result.passed).toBe(true);
    expect(result.toolCount).toBe(3);
    expect(result.error).toBeNull();
  });

  it("returns tier 3 pass with zero tools", async () => {
    const toolsResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [] },
    });
    mockSpawn.mockReturnValue(createMockChild(toolsResponse));

    const entry: McpServerEntry = { command: "npx", args: [] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(3);
    expect(result.passed).toBe(true);
    expect(result.toolCount).toBe(0);
  });

  // -------------------------------------------------------------------------
  // Environment and misc
  // -------------------------------------------------------------------------

  it("passes environment variables to the spawned process", async () => {
    mockSpawn.mockReturnValue(createMockChild(""));
    const entry: McpServerEntry = { command: "npx", args: [], env: { DB_URL: "postgres://localhost" } };
    await runHealthCheck(entry, { EXTRA_VAR: "value" });

    expect(mockSpawn).toHaveBeenCalledOnce();
    const callEnv = mockSpawn.mock.calls[0][2].env;
    expect(callEnv.DB_URL).toBe("postgres://localhost");
    expect(callEnv.EXTRA_VAR).toBe("value");
  });

  it("includes durationMs in result", async () => {
    mockSpawn.mockReturnValue(createMockChild(""));
    const entry: McpServerEntry = { command: "npx", args: [] };
    const result = await runHealthCheck(entry);
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("skips non-JSON lines in output gracefully", async () => {
    const toolsResponse = JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      result: { tools: [{ name: "tool_a" }] },
    });
    mockSpawn.mockReturnValue(createMockChild(`Some debug log\n${toolsResponse}\nAnother log line`));

    const entry: McpServerEntry = { command: "npx", args: [] };
    const result = await runHealthCheck(entry);
    expect(result.tier).toBe(3);
    expect(result.passed).toBe(true);
    expect(result.toolCount).toBe(1);
  });
});
