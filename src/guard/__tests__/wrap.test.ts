/**
 * Tests for wrap.ts — entry transformation + detection (Next Step 5).
 */

import { describe, expect, test } from "vitest";
import {
  wrapEntry,
  unwrapEntry,
  isWrapped,
  getWrappedServerName,
  resolveMcpmBinaryPath,
  defaultWrapContext,
  type WrapContext,
} from "../wrap.js";

const ctx: WrapContext = { mcpmBinary: "/abs/path/to/node", scriptPath: "/abs/path/to/dist/index.js" };

describe("wrapEntry", () => {
  test("wraps a stdio server preserving env + adding wrap marker", () => {
    const orig = {
      command: "npx",
      args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      env: { FOO: "bar" },
    };
    const wrapped = wrapEntry("fs-mcp", orig, ctx);
    expect(wrapped.command).toBe("/abs/path/to/node");
    expect(wrapped.args).toEqual([
      "/abs/path/to/dist/index.js",
      "guard", "run", "--inner",
      "--server-name", "fs-mcp",
      "--",
      "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data",
    ]);
    expect(wrapped.env).toEqual({ FOO: "bar" });
  });

  test("wraps a server with no args", () => {
    const wrapped = wrapEntry("bare", { command: "my-server" }, ctx);
    expect(wrapped.args).toEqual([
      "/abs/path/to/dist/index.js",
      "guard", "run", "--inner",
      "--server-name", "bare",
      "--",
      "my-server",
    ]);
  });

  test("does not include env field when original had no env", () => {
    const wrapped = wrapEntry("bare", { command: "my-server" }, ctx);
    expect(wrapped.env).toBeUndefined();
  });

  test("preserves disabled flag", () => {
    const wrapped = wrapEntry("d", { command: "x", disabled: true }, ctx);
    expect(wrapped.disabled).toBe(true);
  });

  test("never mutates the original entry", () => {
    const orig = { command: "npx", args: ["-y", "foo"], env: { K: "V" } };
    const frozen = Object.freeze({ ...orig, args: Object.freeze([...orig.args]), env: Object.freeze({ ...orig.env }) });
    expect(() => wrapEntry("x", frozen, ctx)).not.toThrow();
  });

  test("throws when the entry has no command (HTTP-transport server)", () => {
    expect(() => wrapEntry("http-mcp", { url: "https://example.com" }, ctx)).toThrow(
      /no command/,
    );
  });
});

describe("isWrapped + unwrapEntry round-trip", () => {
  test("round-trips a typical entry", () => {
    const orig = {
      command: "npx",
      args: ["-y", "@org/server-x"],
      env: { KEY: "val" },
    };
    const wrapped = wrapEntry("server-x", orig, { mcpmBinary: "mcpm" });
    expect(isWrapped(wrapped)).toBe(true);
    const unwrapped = unwrapEntry(wrapped);
    expect(unwrapped).toEqual(orig);
  });

  test("isWrapped returns false on unwrapped entry", () => {
    expect(isWrapped({ command: "npx", args: ["-y", "foo"] })).toBe(false);
  });

  test("isWrapped returns false on entry with no args", () => {
    expect(isWrapped({ command: "node" })).toBe(false);
  });

  test("unwrapEntry returns null on unwrapped entry", () => {
    expect(unwrapEntry({ command: "npx", args: ["-y", "foo"] })).toBeNull();
  });

  test("unwrapEntry returns null on malformed wrap (missing -- separator)", () => {
    // Marker present but no -- separator following
    const malformed = {
      command: "mcpm",
      args: ["guard", "run", "--inner", "--server-name", "x"],
    };
    expect(unwrapEntry(malformed)).toBeNull();
  });

  test("getWrappedServerName extracts the name", () => {
    const wrapped = wrapEntry("my-server", { command: "x" }, { mcpmBinary: "mcpm" });
    expect(getWrappedServerName(wrapped)).toBe("my-server");
  });
});

describe("resolveMcpmBinaryPath / defaultWrapContext", () => {
  test("uses node + script when script is dist/index.js", () => {
    const ctx = defaultWrapContext(["/usr/local/bin/node", "/abs/dist/index.js", "guard", "enable"]);
    expect(ctx.mcpmBinary).toBe("/usr/local/bin/node");
    expect(ctx.scriptPath).toBe("/abs/dist/index.js");
  });

  test("falls back to bare 'mcpm' for non-dist scripts (shim)", () => {
    const path = resolveMcpmBinaryPath(["/usr/local/bin/node", "/some/shim", "guard"]);
    expect(path).toBe("mcpm");
  });
});
