import { describe, it, expect, vi } from "vitest";
import { handleDiff } from "../../commands/diff.js";
import type { DiffDeps } from "../../commands/diff.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAdapter(servers: Record<string, McpServerEntry> = {}) {
  return { read: vi.fn().mockResolvedValue({ ...servers }) };
}

function makeDeps(overrides: Partial<DiffDeps> = {}): DiffDeps {
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
    getAdapter: vi.fn().mockReturnValue(makeAdapter()),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    output: vi.fn(),
    ...overrides,
  };
}

async function writeStackAndLock(
  stackYaml: string,
  lockYaml: string
): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-diff-test-"));
  await writeFile(path.join(dir, "mcpm.yaml"), stackYaml, "utf-8");
  await writeFile(path.join(dir, "mcpm-lock.yaml"), lockYaml, "utf-8");
  return path.join(dir, "mcpm.yaml");
}

const basicStack = `
version: "1"
servers:
  io.github.test/server-a:
    version: "^1.0.0"
`;

const basicLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.2.0"
    registryType: npm
    identifier: "@test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleDiff", () => {
  it("shows missing servers (in yaml but not installed)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps(); // empty installed

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("Missing");
    expect(outputCalls).toContain("server-a");
  });

  it("shows extra servers (installed but not in yaml)", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          "io.github.test/server-a": { command: "npx", args: ["-y", "server-a"] },
          "extra-server": { command: "npx", args: ["-y", "extra"] },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("Extra");
    expect(outputCalls).toContain("extra-server");
  });

  it("shows in-sync servers with trust info", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          "io.github.test/server-a": { command: "npx", args: ["-y", "server-a"] },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("In sync");
    expect(outputCalls).toContain("v1.2.0");
    expect(outputCalls).toContain("75/80");
  });

  it("outputs JSON with --json flag", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          "io.github.test/server-a": { command: "npx", args: ["-y", "server-a"] },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath, json: true }, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = JSON.parse(outputCall);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed[0].name).toBe("io.github.test/server-a");
    expect(parsed[0].status).toBe("match");
  });

  it("throws when no lock file exists", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-diff-nolock-"));
    const stackPath = path.join(dir, "mcpm.yaml");
    await writeFile(stackPath, basicStack, "utf-8");

    const deps = makeDeps();
    await expect(handleDiff({ stackFile: stackPath }, deps)).rejects.toThrow(
      "No lock file found"
    );
  });
});
