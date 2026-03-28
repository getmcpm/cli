/**
 * Tests for src/commands/init.ts — written FIRST per TDD (Red → Green → Refactor).
 *
 * Strategy:
 * - installServer is injected as a mock — init does not implement install inline.
 * - Test handler directly — not Commander parsing.
 * - Cover: valid pack, invalid pack, no pack name (lists packs), partial failure,
 *   --yes passes through, --client passes through.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Types (mirrors handler's injectable deps)
// ---------------------------------------------------------------------------

interface InstallResult {
  success: boolean;
  error?: string;
}

interface InitOptions {
  yes?: boolean;
  client?: string;
}

interface InitDeps {
  installServer: (name: string, options: { yes: boolean; client?: string }) => Promise<InstallResult>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

import { handleInit, PACKS } from "../../commands/init.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeDeps(overrides: Partial<InitDeps> = {}): InitDeps {
  return {
    installServer: vi.fn().mockResolvedValue({ success: true }),
    output: vi.fn(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// No pack name — list available packs
// ---------------------------------------------------------------------------

describe("handleInit — no pack name", () => {
  it("lists available pack names when no argument is provided", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit(undefined, {}, deps);
    const out = lines.join("\n");
    expect(out).toContain("developer");
    expect(out).toContain("data");
    expect(out).toContain("web");
  });

  it("shows descriptions for each pack", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit(undefined, {}, deps);
    const out = lines.join("\n");
    // Each pack has a description
    expect(out.length).toBeGreaterThan(50);
  });

  it("does not call installServer when no pack name is given", async () => {
    const deps = makeDeps();
    await handleInit(undefined, {}, deps);
    expect(deps.installServer).not.toHaveBeenCalled();
  });

  it("shows usage hint", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit(undefined, {}, deps);
    expect(lines.join("\n")).toMatch(/mcpm init/i);
  });
});

// ---------------------------------------------------------------------------
// Invalid pack name
// ---------------------------------------------------------------------------

describe("handleInit — invalid pack name", () => {
  it("outputs an error message for unknown pack names", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit("nonexistent-pack", {}, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/unknown pack/i);
    expect(out).toContain("nonexistent-pack");
  });

  it("lists available packs in the error message", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit("bad-pack", {}, deps);
    const out = lines.join("\n");
    expect(out).toContain("developer");
    expect(out).toContain("data");
    expect(out).toContain("web");
  });

  it("does not call installServer for unknown pack names", async () => {
    const deps = makeDeps();
    await handleInit("invalid", {}, deps);
    expect(deps.installServer).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Valid pack — developer
// ---------------------------------------------------------------------------

describe("handleInit — developer pack", () => {
  beforeEach(() => vi.clearAllMocks());

  it("calls installServer for each server in the developer pack", async () => {
    const deps = makeDeps();
    await handleInit("developer", { yes: true }, deps);
    const developerPack = PACKS["developer"];
    expect(deps.installServer).toHaveBeenCalledTimes(developerPack.servers.length);
    for (const serverName of developerPack.servers) {
      expect(deps.installServer).toHaveBeenCalledWith(
        serverName,
        expect.objectContaining({ yes: true })
      );
    }
  });

  it("outputs success message after installing the pack", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit("developer", { yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/installed|developer/i);
  });

  it("reports the count of installed servers", async () => {
    const lines: string[] = [];
    const deps = makeDeps({ output: (t) => lines.push(t) });
    await handleInit("developer", { yes: true }, deps);
    const out = lines.join("\n");
    const count = PACKS["developer"].servers.length;
    expect(out).toContain(String(count));
  });
});

// ---------------------------------------------------------------------------
// Valid pack — data
// ---------------------------------------------------------------------------

describe("handleInit — data pack", () => {
  it("calls installServer for each server in the data pack", async () => {
    const deps = makeDeps();
    await handleInit("data", { yes: true }, deps);
    const dataPack = PACKS["data"];
    expect(deps.installServer).toHaveBeenCalledTimes(dataPack.servers.length);
  });
});

// ---------------------------------------------------------------------------
// Valid pack — web
// ---------------------------------------------------------------------------

describe("handleInit — web pack", () => {
  it("calls installServer for each server in the web pack", async () => {
    const deps = makeDeps();
    await handleInit("web", { yes: true }, deps);
    const webPack = PACKS["web"];
    expect(deps.installServer).toHaveBeenCalledTimes(webPack.servers.length);
  });
});

// ---------------------------------------------------------------------------
// Partial failure — 2/3 succeed
// ---------------------------------------------------------------------------

describe("handleInit — partial failure", () => {
  it("continues installing other servers when one fails", async () => {
    const deps = makeDeps({
      installServer: vi.fn()
        .mockResolvedValueOnce({ success: true })
        .mockResolvedValueOnce({ success: false, error: "not found in registry" })
        .mockResolvedValueOnce({ success: true }),
    });
    await handleInit("developer", { yes: true }, deps);
    const count = PACKS["developer"].servers.length;
    expect(deps.installServer).toHaveBeenCalledTimes(count);
  });

  it("reports how many succeeded and which failed", async () => {
    const lines: string[] = [];
    const developerServers = PACKS["developer"].servers;
    const failingServerName = developerServers[1]; // second server fails

    const deps = makeDeps({
      installServer: vi.fn()
        .mockResolvedValueOnce({ success: true })
        .mockResolvedValueOnce({ success: false, error: "not found in registry" })
        .mockResolvedValueOnce({ success: true }),
      output: (t) => lines.push(t),
    });
    await handleInit("developer", { yes: true }, deps);
    const out = lines.join("\n");

    // Report: "Installed 2/3 servers from 'developer' pack"
    expect(out).toMatch(/2.*3|installed.*2/i);
    // Mention the failing server
    expect(out).toContain(failingServerName);
  });

  it("shows 'Failed:' section listing the failed server names", async () => {
    const lines: string[] = [];
    const failingServer = PACKS["developer"].servers[0];

    const deps = makeDeps({
      installServer: vi.fn()
        .mockResolvedValueOnce({ success: false, error: "not found" })
        .mockResolvedValue({ success: true }),
      output: (t) => lines.push(t),
    });
    await handleInit("developer", { yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/failed/i);
    expect(out).toContain(failingServer);
  });
});

// ---------------------------------------------------------------------------
// All fail
// ---------------------------------------------------------------------------

describe("handleInit — all servers fail", () => {
  it("reports 0 installed when all fail", async () => {
    const lines: string[] = [];
    const deps = makeDeps({
      installServer: vi.fn().mockResolvedValue({ success: false, error: "not found" }),
      output: (t) => lines.push(t),
    });
    await handleInit("developer", { yes: true }, deps);
    const out = lines.join("\n");
    expect(out).toMatch(/0.*installed|installed.*0/i);
  });
});

// ---------------------------------------------------------------------------
// --yes passes through
// ---------------------------------------------------------------------------

describe("handleInit — --yes option", () => {
  it("passes yes: true to installServer when --yes is set", async () => {
    const deps = makeDeps();
    await handleInit("developer", { yes: true }, deps);
    for (const call of (deps.installServer as ReturnType<typeof vi.fn>).mock.calls) {
      expect(call[1]).toMatchObject({ yes: true });
    }
  });

  it("passes yes: false when --yes is not set", async () => {
    const deps = makeDeps();
    await handleInit("developer", { yes: false }, deps);
    for (const call of (deps.installServer as ReturnType<typeof vi.fn>).mock.calls) {
      expect(call[1]).toMatchObject({ yes: false });
    }
  });
});

// ---------------------------------------------------------------------------
// --client passes through
// ---------------------------------------------------------------------------

describe("handleInit — --client option", () => {
  it("passes client to installServer when --client is provided", async () => {
    const deps = makeDeps();
    await handleInit("developer", { yes: true, client: "cursor" }, deps);
    for (const call of (deps.installServer as ReturnType<typeof vi.fn>).mock.calls) {
      expect(call[1]).toMatchObject({ client: "cursor" });
    }
  });

  it("does not pass client when --client is not provided", async () => {
    const deps = makeDeps();
    await handleInit("developer", { yes: true }, deps);
    for (const call of (deps.installServer as ReturnType<typeof vi.fn>).mock.calls) {
      expect(call[1].client).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// PACKS exported constant
// ---------------------------------------------------------------------------

describe("PACKS constant", () => {
  it("has developer, data, and web packs", () => {
    expect(PACKS).toHaveProperty("developer");
    expect(PACKS).toHaveProperty("data");
    expect(PACKS).toHaveProperty("web");
  });

  it("each pack has a description and servers array", () => {
    for (const [, pack] of Object.entries(PACKS)) {
      expect(pack).toHaveProperty("description");
      expect(pack).toHaveProperty("servers");
      expect(Array.isArray(pack.servers)).toBe(true);
      expect(pack.servers.length).toBeGreaterThan(0);
    }
  });

  it("developer pack has at least filesystem and git servers", () => {
    const servers = PACKS["developer"].servers;
    const hasFilesystem = servers.some((s) => s.toLowerCase().includes("filesystem"));
    const hasGit = servers.some((s) => s.toLowerCase().includes("git"));
    expect(hasFilesystem).toBe(true);
    expect(hasGit).toBe(true);
  });

  it("data pack contains database-related servers", () => {
    const servers = PACKS["data"].servers;
    const hasDb = servers.some(
      (s) => s.toLowerCase().includes("postgres") || s.toLowerCase().includes("sqlite")
    );
    expect(hasDb).toBe(true);
  });

  it("web pack contains fetch or browser servers", () => {
    const servers = PACKS["web"].servers;
    const hasFetchOrBrowser = servers.some(
      (s) => s.toLowerCase().includes("fetch") || s.toLowerCase().includes("browser") || s.toLowerCase().includes("puppeteer")
    );
    expect(hasFetchOrBrowser).toBe(true);
  });
});
