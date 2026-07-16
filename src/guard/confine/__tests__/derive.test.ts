import os from "node:os";
import path from "node:path";
import { describe, expect, test } from "vitest";
import { CLIENT_IDS, getConfigPath } from "../../../config/paths.js";
import {
  classifyNet,
  deriveDefaultProfile,
  safeServerSegment,
  SECRET_DIR_SEGMENTS,
  type DeriveInput,
} from "../derive.js";

const input = (over: Partial<DeriveInput> = {}): DeriveInput => ({
  serverName: "filesystem",
  command: "node",
  args: ["server.js"],
  home: "/home/u",
  sandboxRoot: "/home/u/.mcpm/sandbox",
  tmpDir: "/tmp",
  capturedAt: "2026-01-01T00:00:00Z",
  ...over,
});

describe("classifyNet", () => {
  test("launcher commands that fetch at launch get 'all'", () => {
    for (const c of ["npx", "uvx", "pip", "pipx", "docker", "/usr/local/bin/npx", "npx.cmd"]) {
      expect(classifyNet(c)).toBe("all");
    }
  });
  test("non-launcher commands default to egress-deny 'none'", () => {
    for (const c of ["node", "python3", "/opt/bin/my-server", "deno"]) {
      expect(classifyNet(c)).toBe("none");
    }
  });
});

describe("safeServerSegment", () => {
  test("neutralizes path separators and traversal, stays unique via hash suffix", () => {
    const a = safeServerSegment("io.github.foo/bar");
    expect(a).not.toContain("/");
    expect(a).toMatch(/-[0-9a-f]{8}$/);
    // "a/b" and "a_b" sanitize to the same cleaned stem but differ by hash suffix.
    expect(safeServerSegment("a/b")).not.toBe(safeServerSegment("a_b"));
  });
  test("neutralizes leading dots (no '.'/'..' segment) and rejects empty", () => {
    expect(safeServerSegment("..")).not.toMatch(/^\.\.-/);
    expect(safeServerSegment("..").startsWith("_")).toBe(true);
    expect(() => safeServerSegment("")).toThrow();
  });
  test("collapses interior '..' runs so no '..' survives in the segment", () => {
    expect(safeServerSegment("a..b")).not.toContain("..");
    expect(safeServerSegment("x/../../y")).not.toContain("..");
  });
});

describe("deriveDefaultProfile", () => {
  test("standard tier: read-denies the secret dirs, absolute under home", () => {
    const p = deriveDefaultProfile(input());
    expect(p.tier).toBe("standard");
    expect(p.read_deny).toContain("/home/u/.ssh");
    expect(p.read_deny).toContain("/home/u/.aws");
    expect(p.read_deny).toContain("/home/u/Library/Keychains");
    expect(p.read_deny).toContain("/home/u/.mcpm");
    // Sibling MCP client configs holding plaintext env secrets must be denied too:
    // Claude Code (~/.claude.json + ~/.claude state) and Gemini CLI (~/.gemini).
    expect(p.read_deny).toContain("/home/u/.claude.json");
    expect(p.read_deny).toContain("/home/u/.claude");
    expect(p.read_deny).toContain("/home/u/.gemini");
    // Every configured secret segment is present.
    expect(p.read_deny.length).toBe(new Set(SECRET_DIR_SEGMENTS).size);
    expect(p.read_deny.every((d) => d.startsWith("/home/u/"))).toBe(true);
  });

  test("write-allow includes scratch + temp + launcher caches, denies the rest of $HOME", () => {
    const p = deriveDefaultProfile(input());
    expect(p.write_allow).toContain(p.scratch_dir);
    expect(p.write_allow).toContain("/tmp");
    expect(p.write_allow).toContain("/home/u/.npm");
    expect(p.write_allow).toContain("/home/u/.cache");
    // No blanket $HOME write (that would defeat persistence-blocking).
    expect(p.write_allow).not.toContain("/home/u");
  });

  test("scratch dir is under sandboxRoot and traversal-safe", () => {
    const p = deriveDefaultProfile(input({ serverName: "../evil" }));
    expect(p.scratch_dir.startsWith("/home/u/.mcpm/sandbox/")).toBe(true);
    expect(p.scratch_dir).not.toContain("..");
  });

  test("net follows the launcher classifier but is overridable; require_confine flows", () => {
    expect(deriveDefaultProfile(input({ command: "npx" })).net).toBe("all");
    expect(deriveDefaultProfile(input({ command: "node" })).net).toBe("none");
    expect(deriveDefaultProfile(input({ command: "npx", net: "none" })).net).toBe("none");
    expect(deriveDefaultProfile(input({ requireConfine: true })).require_confine).toBe(true);
  });

  test("read_deny + write_allow are sorted (stable content hash)", () => {
    const p = deriveDefaultProfile(input());
    expect([...p.read_deny]).toEqual([...p.read_deny].sort());
    expect([...p.write_allow]).toEqual([...p.write_allow].sort());
  });

  test("throws on an empty command (caller-contract guard)", () => {
    expect(() => deriveDefaultProfile(input({ command: "" }))).toThrow();
  });
});

describe("SECRET_DIR_SEGMENTS drift guard", () => {
  // The confine read-denylist must cover every first-class client's config file
  // (each can hold another server's plaintext env secrets). derive.ts is a pure,
  // I/O-free function so it stays testable on ubuntu-only CI — the denylist is
  // therefore hand-maintained. This test fails the build if a client adapter is
  // added without denying its config path (the exact drift the 2026-07-14 review
  // caught: .claude.json / .gemini were missing). macOS paths — confine is macOS-only.
  const components = (p: string): string[] => p.split(/[\\/]+/).filter(Boolean);
  const deniedSegments = SECRET_DIR_SEGMENTS.map(components);
  const isCovered = (relComponents: string[]): boolean =>
    deniedSegments.some((seg) => seg.every((c, i) => relComponents[i] === c));

  for (const id of CLIENT_IDS) {
    test(`client "${id}" config path is under a denied secret segment`, () => {
      const home = os.homedir();
      const rel = path.relative(home, getConfigPath(id, "darwin"));
      expect(rel.startsWith("..")).toBe(false); // sanity: config lives under $HOME
      expect(isCovered(components(rel))).toBe(true);
    });
  }
});
