import { describe, it, expect, vi } from "vitest";
import { handleExport } from "../../commands/export.js";
import type { ExportDeps, ExportOptions } from "../../commands/export.js";
import type { ClientId } from "../../config/paths.js";
import type { McpServerEntry } from "../../config/adapters/index.js";
import { parse as parseYaml } from "yaml";
import { StackFileSchema } from "../../stack/schema.js";

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
});
