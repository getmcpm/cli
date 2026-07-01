import { afterEach, describe, expect, test } from "vitest";
import {
  buildMacosWrap,
  isMacosBackendAvailable,
  renderSbpl,
  sanitizePathForSBPL,
  SANDBOX_EXEC_PATH,
} from "../backend-macos.js";
import type { ConfineProfile } from "../profile.js";

const profile = (over: Partial<ConfineProfile> = {}): ConfineProfile => ({
  tier: "standard",
  require_confine: false,
  read_deny: ["/home/u/.ssh", "/home/u/.aws"],
  write_allow: ["/home/u/.mcpm/sandbox/x", "/tmp"],
  net: "none",
  scratch_dir: "/home/u/.mcpm/sandbox/x",
  captured_at: "2026-01-01T00:00:00Z",
  ...over,
});

describe("renderSbpl", () => {
  test("emits allow-default, then deny-write + write-allowlist, then read-denylist (order matters)", () => {
    const sb = renderSbpl(profile());
    expect(sb).toContain("(version 1)");
    expect(sb).toContain("(allow default)");
    // Ordering: allow default → deny file-write* → allow file-write* → deny file-read*.
    const iAllowDefault = sb.indexOf("(allow default)");
    const iDenyWrite = sb.indexOf("(deny file-write*)");
    const iAllowWrite = sb.indexOf("(allow file-write*");
    const iDenyRead = sb.indexOf("(deny file-read*");
    expect(iAllowDefault).toBeLessThan(iDenyWrite);
    expect(iDenyWrite).toBeLessThan(iAllowWrite);
    expect(iAllowWrite).toBeLessThan(iDenyRead);
    expect(sb).toContain('(subpath "/home/u/.ssh")');
    expect(sb).toContain('(subpath "/tmp")');
  });

  test("net='none' denies network; net='all' does not", () => {
    expect(renderSbpl(profile({ net: "none" }))).toContain("(deny network*)");
    expect(renderSbpl(profile({ net: "all" }))).not.toContain("(deny network*)");
  });

  test("re-allows reads within scratch AFTER the read-deny (scratch under ~/.mcpm is not write-only)", () => {
    const sb = renderSbpl(
      profile({ scratch_dir: "/home/u/.mcpm/sandbox/x", read_deny: ["/home/u/.mcpm"] }),
    );
    const iDenyRead = sb.indexOf("(deny file-read*");
    const iAllowScratch = sb.indexOf('(allow file-read* (subpath "/home/u/.mcpm/sandbox/x")');
    expect(iAllowScratch).toBeGreaterThan(iDenyRead); // last-match-wins re-permits scratch
  });
});

describe("sanitizePathForSBPL", () => {
  test("leaves spaces, escapes quote and backslash", () => {
    expect(sanitizePathForSBPL("/a/Application Support/Claude")).toBe(
      "/a/Application Support/Claude",
    );
    expect(sanitizePathForSBPL('/a/"weird"')).toBe('/a/\\"weird\\"');
    expect(sanitizePathForSBPL("/a/b\\c")).toBe("/a/b\\\\c");
  });

  test("refuses a path containing a control character (injection guard)", () => {
    const withCtrl = `/a/${String.fromCharCode(1)}b`;
    expect(() => sanitizePathForSBPL(withCtrl)).toThrow(/control character/);
  });
});

describe("buildMacosWrap", () => {
  test("wraps command+args under sandbox-exec -p <profile> (no -- separator)", () => {
    const w = buildMacosWrap(profile(), "node", ["server.js", "--port", "3000"]);
    expect(w.command).toBe(SANDBOX_EXEC_PATH);
    expect(w.args[0]).toBe("-p");
    expect(w.args[1]).toContain("(version 1)");
    expect(w.args.slice(2)).toEqual(["node", "server.js", "--port", "3000"]);
  });
});

describe("isMacosBackendAvailable", () => {
  afterEach(() => {
    delete process.env.MCPM_DISABLE_CONFINE;
  });
  test("MCPM_DISABLE_CONFINE=1 forces unavailable regardless of platform", () => {
    process.env.MCPM_DISABLE_CONFINE = "1";
    expect(isMacosBackendAvailable()).toBe(false);
  });
});
