import { describe, expect, test } from "vitest";
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
