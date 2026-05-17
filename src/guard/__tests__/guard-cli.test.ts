/**
 * Integration tests for `mcpm guard run --inner` Commander parsing
 * (security review F1 regression guard).
 *
 * The previous parser ran a hand-rolled indexOf over cmd.args, which Commander
 * had already stripped of --server-name. That meant the relay never started
 * for any wrapped server. These tests exercise the full Commander parse path
 * so the same class of bug can't recur silently.
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { Command } from "commander";
import { registerGuardCommand } from "../../commands/guard.js";

let exitSpy: ReturnType<typeof vi.spyOn>;
let stderrSpy: ReturnType<typeof vi.spyOn>;
let runInnerCalls: Array<{ serverName: string; command: string; args: readonly string[] }>;

beforeEach(() => {
  exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
    throw new Error("__EXIT__");
  }) as never);
  stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  runInnerCalls = [];
  vi.doMock("../run-inner.js", () => ({
    runInner: async (args: { serverName: string; command: string; args: readonly string[] }) => {
      runInnerCalls.push(args);
      return 0;
    },
  }));
});

afterEach(() => {
  exitSpy.mockRestore();
  stderrSpy.mockRestore();
  vi.doUnmock("../run-inner.js");
});

async function runArgv(argv: readonly string[]): Promise<void> {
  const program = new Command();
  program.exitOverride(); // throw instead of process.exit on parse errors
  registerGuardCommand(program);
  try {
    await program.parseAsync(["node", "mcpm", ...argv]);
  } catch (err) {
    if (err instanceof Error && err.message === "__EXIT__") return;
    throw err;
  }
}

describe("mcpm guard run --inner argv parsing through Commander", () => {
  test("parses --server-name + -- separator + command + args", async () => {
    await runArgv([
      "guard", "run", "--inner",
      "--server-name", "fs-mcp",
      "--",
      "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data",
    ]);
    expect(runInnerCalls).toHaveLength(1);
    expect(runInnerCalls[0]).toEqual({
      serverName: "fs-mcp",
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
    });
  });

  test("refuses run --inner without the --inner marker (security F6)", async () => {
    await runArgv([
      "guard", "run",
      "--server-name", "fs-mcp",
      "--",
      "npx",
    ]);
    expect(runInnerCalls).toHaveLength(0);
    expect(exitSpy).toHaveBeenCalledWith(1);
    const calls = stderrSpy.mock.calls.flat().join("");
    expect(calls).toContain("--inner flag required");
  });

  test("errors when --server-name is missing", async () => {
    await runArgv([
      "guard", "run", "--inner",
      "--",
      "npx",
    ]);
    expect(runInnerCalls).toHaveLength(0);
    expect(exitSpy).toHaveBeenCalledWith(1);
    const calls = stderrSpy.mock.calls.flat().join("");
    expect(calls).toContain("missing --server-name");
  });

  test("errors when no command follows the -- separator", async () => {
    await runArgv([
      "guard", "run", "--inner",
      "--server-name", "fs-mcp",
      "--",
    ]);
    expect(runInnerCalls).toHaveLength(0);
    expect(exitSpy).toHaveBeenCalledWith(1);
    const calls = stderrSpy.mock.calls.flat().join("");
    expect(calls).toContain("missing -- <command>");
  });

  test("passes flag-shaped child args through (no Commander reinterpretation)", async () => {
    // The wrapped server may take its own flags; Commander must not eat them.
    await runArgv([
      "guard", "run", "--inner",
      "--server-name", "x",
      "--",
      "node", "--inspect", "/some/server.js", "--port", "8080",
    ]);
    expect(runInnerCalls[0]?.command).toBe("node");
    expect(runInnerCalls[0]?.args).toEqual(["--inspect", "/some/server.js", "--port", "8080"]);
  });
});
