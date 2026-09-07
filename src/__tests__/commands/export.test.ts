import { describe, it, expect, vi } from "vitest";
import { handleExport } from "../../commands/export.js";
import type { ExportDeps, ExportOptions } from "../../commands/export.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import { parse as parseYaml } from "yaml";
import { StackFileSchema, parseStackFile } from "../../stack/schema.js";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeAdapter(servers: Record<string, McpServerEntry> = {}) {
  return {
    read: vi.fn().mockResolvedValue(servers),
  };
}

function makeDeps(overrides: Partial<ExportDeps> = {}): ExportDeps {
  return {
    detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue([
      "claude-desktop",
      "cursor",
    ]),
    getAdapter: vi.fn().mockReturnValue(makeAdapter()),
    getPath: vi.fn().mockReturnValue("/mock/config.json"),
    writeFile: vi.fn().mockResolvedValue(undefined),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("handleExport", () => {
  it("exports servers across multiple clients as valid YAML", async () => {
    const claudeServers: Record<string, McpServerEntry> = {
      "io.github.domdomegg/filesystem-mcp": {
        command: "npx",
        args: ["-y", "filesystem-mcp"],
      },
    };
    const cursorServers: Record<string, McpServerEntry> = {
      "io.github.other/server": {
        command: "uvx",
        args: ["other-server"],
      },
    };

    const deps = makeDeps({
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) =>
        makeAdapter(
          clientId === "claude-desktop" ? claudeServers : cursorServers
        )
      ),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    const result = StackFileSchema.safeParse(parsed);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(Object.keys(result.data.servers)).toHaveLength(2);
    }
  });

  it("outputs empty YAML with version header when no servers installed", async () => {
    const deps = makeDeps();
    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    expect(parsed.version).toBe("1");
    expect(parsed.servers).toEqual({});
  });

  it("deduplicates by server name using first-seen-wins", async () => {
    const server: McpServerEntry = {
      command: "npx",
      args: ["-y", "shared-server"],
    };
    const serverWithDiffArgs: McpServerEntry = {
      command: "npx",
      args: ["-y", "shared-server", "--verbose"],
    };

    const deps = makeDeps({
      getAdapter: vi.fn().mockImplementation((clientId: ClientId) =>
        makeAdapter({
          "shared-server":
            clientId === "claude-desktop" ? server : serverWithDiffArgs,
        })
      ),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    expect(Object.keys(parsed.servers)).toHaveLength(1);
  });

  it("exports env var keys only without actual values", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-server": {
        command: "npx",
        args: ["-y", "my-server"],
        env: { GITHUB_TOKEN: "ghp_secret123", DB_PATH: "./data.db" },
      },
    };

    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    const env = parsed.servers["my-server"].env;
    expect(env.GITHUB_TOKEN).toBeDefined();
    expect(env.GITHUB_TOKEN.required).toBe(true);
    // Actual value must not appear
    expect(outputCall).not.toContain("ghp_secret123");
  });

  it("writes to file when --output is specified", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-server": { command: "npx", args: ["-y", "my-server"] },
    };
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({ output: "/tmp/mcpm.yaml" }, deps);

    expect(deps.writeFile).toHaveBeenCalledWith(
      "/tmp/mcpm.yaml",
      expect.stringContaining("version:")
    );
    const outputMsg = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(outputMsg).toContain("Exported 1 servers");
  });

  it("infers secret from env var names containing TOKEN, KEY, SECRET", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-server": {
        command: "npx",
        args: ["-y", "my-server"],
        env: {
          API_TOKEN: "tok_123",
          API_KEY: "key_456",
          DB_PASSWORD: "pass",
          SIMPLE_VAR: "plain",
        },
      },
    };

    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    const env = parsed.servers["my-server"].env;
    expect(env.API_TOKEN.secret).toBe(true);
    expect(env.API_KEY.secret).toBe(true);
    expect(env.DB_PASSWORD.secret).toBe(true);
    expect(env.SIMPLE_VAR.secret).toBe(false);
  });

  it("exports URL-based servers with url field instead of version", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-remote": {
        url: "https://internal.company.com/mcp",
      },
    };

    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    expect(parsed.servers["my-remote"].url).toBe("https://internal.company.com/mcp");
    expect(parsed.servers["my-remote"].version).toBeUndefined();
  });

  it("skips clients with unreadable configs", async () => {
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue({
        read: vi.fn().mockRejectedValue(new Error("Permission denied")),
      }),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    expect(parsed.servers).toEqual({});
  });

  // --- F4: curated policy default ------------------------------------------

  it("seeds the curated policy default (minReleaseAgeHours: 24)", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-server": { command: "npx", args: ["-y", "my-server"] },
    };
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const parsed = parseYaml(outputCall);
    expect(parsed.policy.minReleaseAgeHours).toBe(24);
    expect(parsed.policy.blockOnScoreDrop).toBe(false);
  });

  it("round-trips the exported file through parseStackFile with the policy intact", async () => {
    const servers: Record<string, McpServerEntry> = {
      "my-server": { command: "npx", args: ["-y", "my-server"] },
    };
    const deps = makeDeps({
      getAdapter: vi.fn().mockReturnValue(makeAdapter(servers)),
    });

    await handleExport({}, deps);

    const outputCall = (deps.output as ReturnType<typeof vi.fn>).mock.calls[0][0];
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-export-test-"));
    const filePath = path.join(dir, "mcpm.yaml");
    await writeFile(filePath, outputCall, "utf-8");

    const stack = await parseStackFile(filePath);
    expect(stack.policy).toEqual({
      blockOnScoreDrop: false,
      minReleaseAgeHours: 24,
    });
    expect(Object.keys(stack.servers)).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// #59: an entry read() dropped is silently ABSENT from the export, and the user
// keeps the result as their declared stack. It must never look complete.
// ---------------------------------------------------------------------------

describe("handleExport — unreadable entries", () => {
  it("names the entries it could not read on stderr", async () => {
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const deps = makeDeps({
        detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
        getAdapter: vi.fn().mockReturnValue({
          read: vi.fn().mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
            onSkip?.("broken-server");
            return { ok: { command: "npx", args: ["-y", "ok"] } };
          }),
        }),
      });
      await handleExport({} as ExportOptions, deps);
      expect(errs.join("")).toContain("broken-server");
      expect(errs.join("")).toMatch(/NOT in this export/);
    } finally {
      spy.mockRestore();
    }
  });

  it("stays quiet when ANOTHER client supplied a readable copy of the same name", async () => {
    // Found by dogfooding: warning "NOT in this export" about a server the
    // export DOES contain (via the other client) is its own false statement.
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const deps = makeDeps({
        detectClients: vi
          .fn<() => Promise<ClientId[]>>()
          .mockResolvedValue(["claude-desktop", "cursor"]),
        getAdapter: vi.fn().mockImplementation((id: ClientId) =>
          id === "claude-desktop"
            ? {
                read: vi
                  .fn()
                  .mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
                    onSkip?.("shared");
                    return {};
                  }),
              }
            : makeAdapter({ shared: { command: "npx", args: ["-y", "shared"] } })
        ),
      });
      await handleExport({} as ExportOptions, deps);
      expect(errs.join("")).not.toMatch(/NOT in this export/);
    } finally {
      spy.mockRestore();
    }
  });

  it("sanitizes a config-supplied name before it reaches the terminal", async () => {
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const deps = makeDeps({
        detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
        getAdapter: vi.fn().mockReturnValue({
          read: vi.fn().mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
            onSkip?.("ev\u001b]0;PWNED\u0007il");
            return {};
          }),
        }),
      });
      await handleExport({} as ExportOptions, deps);
      expect(errs.join("")).toContain("PWNED");
      expect(errs.join("")).not.toContain("\u001b");
    } finally {
      spy.mockRestore();
    }
  });

  it("writes nothing to stderr for a fully readable config (negative control)", async () => {
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const deps = makeDeps({
        detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
        getAdapter: vi
          .fn()
          .mockReturnValue(makeAdapter({ ok: { command: "npx", args: ["-y", "ok"] } })),
      });
      await handleExport({} as ExportOptions, deps);
      expect(errs.join("")).not.toMatch(/NOT in this export/);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("handleExport — Object.prototype-named entries", () => {
  it("counts a malformed entry named `toString` (a `name in servers` hazard)", async () => {
    // `name in servers` walks the prototype chain, so "toString" read as
    // already-exported and vanished from both the warning and the count.
    const errs: string[] = [];
    const spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
    try {
      const deps = makeDeps({
        detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
        getAdapter: vi.fn().mockReturnValue({
          read: vi.fn().mockImplementation(async (_p: string, onSkip?: (n: string) => void) => {
            onSkip?.("toString");
            onSkip?.("real");
            return {};
          }),
        }),
      });
      await handleExport({} as ExportOptions, deps);
      const text = errs.join("");
      expect(text).toContain("toString");
      expect(text).toMatch(/2 server entries/);
    } finally {
      spy.mockRestore();
    }
  });
});

// ---------------------------------------------------------------------------
// #65 — a server named `__proto__`
// ---------------------------------------------------------------------------

/**
 * read() now surfaces a well-formed entry named `__proto__` (it used to
 * disappear into the accumulator's prototype). mcpm.yaml still cannot carry
 * it: the stack schema's `z.record` DROPS that key on parse — measured, and
 * only that key; `constructor` / `prototype` / `toString` survive. So export
 * must NAME it rather than emit a file that reads back one server short.
 *
 * The map is built with Object.create(null) on purpose: writing
 * `{ __proto__: entry }` as a literal sets the object's prototype, so the
 * fixture would carry no such server and the test would pass against
 * unmodified code.
 */
function withProtoServer(rest: Record<string, McpServerEntry> = {}) {
  const servers: Record<string, McpServerEntry> = Object.create(null);
  for (const [k, v] of Object.entries(rest)) servers[k] = v;
  servers["__proto__"] = { command: "node", args: ["/tmp/payload.js"] };
  return servers;
}

describe("handleExport — a server named __proto__ (#65)", () => {
  let errs: string[];
  let spy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    errs = [];
    spy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation((chunk: string | Uint8Array) => {
        errs.push(String(chunk));
        return true;
      });
  });
  afterEach(() => spy.mockRestore());

  it("names it on stderr and leaves it out of the stack file", async () => {
    const out = vi.fn();
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi
        .fn()
        .mockReturnValue(
          makeAdapter(withProtoServer({ good: { command: "npx", args: ["-y", "good"] } }))
        ),
      output: out,
    });

    await handleExport({} as ExportOptions, deps);

    expect(errs.join("")).toContain("__proto__");
    expect(errs.join("")).toMatch(/cannot represent that name/);

    const yaml = out.mock.calls.map((c) => String(c[0])).join("\n");
    expect(yaml).toContain("good:");
    expect(yaml).not.toContain("__proto__");
  });

  it("does not confuse it with a malformed entry", async () => {
    // `unreadable` means the entry failed shape validation. This one is
    // perfectly valid and the client launches it — pointing the user at
    // `mcpm doctor` would send them looking for a defect that isn't there.
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi.fn().mockReturnValue(makeAdapter(withProtoServer())),
    });

    await handleExport({} as ExportOptions, deps);

    // Assert the POSITIVE too. Asserting only the absence of the malformed
    // message passes against unfixed code, where the entry vanishes before
    // export sees it and NO message fires at all — a guard that cannot fail.
    expect(errs.join("")).toMatch(/cannot represent that name/);
    expect(errs.join("")).not.toMatch(/could not be read/);
  });

  it("does not ALSO claim it could not be read when another client's copy is malformed", async () => {
    // The reason this name is missing is stated once, and it is not
    // "malformed": client A's copy failing shape validation does not make
    // client B's well-formed copy unreadable. Printing both messages repeats
    // the false statement the #59 fix removed for every other name.
    const bServers: Record<string, McpServerEntry> = Object.create(null);
    bServers["__proto__"] = { command: "node", args: ["/tmp/payload.js"] };

    const deps = makeDeps({
      detectClients: vi
        .fn<() => Promise<ClientId[]>>()
        .mockResolvedValue(["claude-desktop", "cursor"]),
      getAdapter: vi.fn().mockImplementation((id: ClientId) =>
        id === "claude-desktop"
          ? {
              read: vi
                .fn()
                .mockImplementation(async (_p: string, onSkip?: (n: string, r: unknown) => void) => {
                  onSkip?.("__proto__", { command: 123 });
                  return {};
                }),
            }
          : makeAdapter(bServers)
      ),
    });

    await handleExport({} as ExportOptions, deps);

    expect(errs.join("")).toMatch(/cannot represent that name/);
    expect(errs.join("")).not.toMatch(/could not be read/);
  });

  it("stays silent when no server carries the name", async () => {
    const deps = makeDeps({
      detectClients: vi.fn<() => Promise<ClientId[]>>().mockResolvedValue(["claude-desktop"]),
      getAdapter: vi
        .fn()
        .mockReturnValue(makeAdapter({ good: { command: "npx", args: ["-y", "good"] } })),
    });

    await handleExport({} as ExportOptions, deps);

    expect(errs.join("")).not.toMatch(/cannot represent that name/);
  });
});
