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

  it("shows missing URL server with url detail", async () => {
    const urlStack = `
version: "1"
servers:
  my-remote:
    url: "https://internal.company.com/mcp"
`;
    const urlLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  my-remote:
    url: "https://internal.company.com/mcp"
`;
    const stackPath = await writeStackAndLock(urlStack, urlLock);
    const deps = makeDeps(); // empty installed

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("Missing");
    expect(outputCalls).toContain("internal.company.com");
  });

  it("shows 'no servers to compare' when stack file and clients are empty", async () => {
    const emptyStack = `
version: "1"
servers: {}
`;
    const emptyLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers: {}
`;
    const stackPath = await writeStackAndLock(emptyStack, emptyLock);
    const deps = makeDeps();

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("No servers to compare");
  });

  // Fix #7: when the installed version is recoverable from config (OCI image:tag)
  // and differs from the locked version, report a mismatch (not "match").
  it("flags version mismatch when installed OCI tag differs from lock", async () => {
    const ociLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "2.0.0"
    registryType: oci
    identifier: "ghcr.io/test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(basicStack, ociLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          // installed v1.0.0 but lock says v2.0.0
          "io.github.test/server-a": {
            command: "docker",
            args: ["run", "--rm", "-i", "ghcr.io/test/server-a:1.0.0"],
          },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath, json: true }, deps);

    const parsed = JSON.parse(
      (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0]
    ) as Array<{ name: string; status: string; detail: string }>;
    const row = parsed.find((e) => e.name === "io.github.test/server-a")!;
    expect(row.status).toBe("mismatch");
    expect(row.detail).toContain("2.0.0");
    expect(row.detail).toContain("1.0.0");
  });

  it("shows mismatch section in human-readable output", async () => {
    const ociLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "2.0.0"
    registryType: oci
    identifier: "ghcr.io/test/server-a"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(basicStack, ociLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          "io.github.test/server-a": {
            command: "docker",
            args: ["run", "--rm", "-i", "ghcr.io/test/server-a:1.0.0"],
          },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath }, deps);

    const outputCalls = (deps.output as ReturnType<typeof vi.fn>).mock.calls
      .map((c) => c[0])
      .join("\n");
    expect(outputCalls).toContain("Version mismatch");
    expect(outputCalls).toContain("1 mismatched");
  });

  // Fix #7: when the installed version is NOT recoverable from config (npm
  // without a pinned version), do NOT emit a false mismatch — stay "match".
  it("does not flag a mismatch when the installed version is not verifiable", async () => {
    const stackPath = await writeStackAndLock(basicStack, basicLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          "io.github.test/server-a": { command: "npx", args: ["-y", "@test/server-a"] },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath, json: true }, deps);

    const parsed = JSON.parse(
      (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0]
    ) as Array<{ name: string; status: string; detail: string }>;
    const row = parsed.find((e) => e.name === "io.github.test/server-a")!;
    expect(row.status).toBe("match");
    expect(row.detail).toContain("version not verifiable");
  });

  // Fix #3: a SCOPED npm identifier whose pinned version in config differs from
  // the lock must report a mismatch — guards extractInstalledVersion's
  // lastIndexOf('@') logic (the leading scope '@' must not be treated as the
  // version separator).
  it("flags version mismatch for a scoped npm package (installed @scope/pkg@1.2.0 vs lock 1.3.0)", async () => {
    const scopedLock = `
lockfileVersion: 1
lockedAt: "2026-04-05T10:00:00Z"
servers:
  io.github.test/server-a:
    version: "1.3.0"
    registryType: npm
    identifier: "@scope/pkg"
    trust:
      score: 75
      maxPossible: 80
      level: safe
      assessedAt: "2026-04-05T10:00:00Z"
`;
    const stackPath = await writeStackAndLock(basicStack, scopedLock);
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(
        makeAdapter({
          // installed pins @scope/pkg@1.2.0 but lock says 1.3.0
          "io.github.test/server-a": {
            command: "npx",
            args: ["-y", "@scope/pkg@1.2.0"],
          },
        })
      ),
    });

    await handleDiff({ stackFile: stackPath, json: true }, deps);

    const parsed = JSON.parse(
      (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0]
    ) as Array<{ name: string; status: string; detail: string }>;
    const row = parsed.find((e) => e.name === "io.github.test/server-a")!;
    expect(row.status).toBe("mismatch");
    expect(row.detail).toContain("1.3.0");
    expect(row.detail).toContain("1.2.0");
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
