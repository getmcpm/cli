/**
 * Tests for wrap.ts — entry transformation + detection (Next Step 5).
 */

import { describe, expect, test } from "vitest";
import {
  wrapEntry,
  unwrapEntry,
  isWrapped,
  hashOriginalEntry,
  resolveMcpmBinaryPath,
  defaultWrapContext,
  WRAP_ORIG_HASH_FLAG,
  WRAP_DECLARED_ENV_FLAG,
  WRAP_CONFINE_HASH_FLAG,
  WRAP_CONFINE_REQUIRED_FLAG,
  WRAP_ARG_SEPARATOR,
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
      "--declared-env", "FOO",
      "--orig-hash", hashOriginalEntry("npx", ["-y", "@modelcontextprotocol/server-filesystem", "/data"], ["FOO"]),
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
      "--orig-hash", hashOriginalEntry("my-server", [], []),
      "--",
      "my-server",
    ]);
  });

  test("omits --declared-env when the original entry has no env (issue #20)", () => {
    const wrapped = wrapEntry("bare", { command: "my-server" }, ctx);
    expect(wrapped.args).not.toContain(WRAP_DECLARED_ENV_FLAG);
  });

  test("embeds sorted declared env key names (issue #20)", () => {
    const wrapped = wrapEntry(
      "multi",
      { command: "x", env: { ZED: "1", ALPHA: "2", MID: "3" } },
      ctx,
    );
    const idx = wrapped.args!.indexOf(WRAP_DECLARED_ENV_FLAG);
    expect(idx).toBeGreaterThan(-1);
    expect(wrapped.args![idx + 1]).toBe("ALPHA,MID,ZED");
  });

  test("embeds an --orig-hash integrity marker (issue #29)", () => {
    const wrapped = wrapEntry("h", { command: "x", args: ["a"] }, ctx);
    const idx = wrapped.args!.indexOf(WRAP_ORIG_HASH_FLAG);
    expect(idx).toBeGreaterThan(-1);
    expect(wrapped.args![idx + 1]).toBe(hashOriginalEntry("x", ["a"], []));
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
});

describe("unwrapEntry integrity verification (issue #29)", () => {
  test("refuses to unwrap when the wrapped command is tampered", () => {
    const wrapped = wrapEntry(
      "victim",
      { command: "npx", args: ["-y", "@org/good"] },
      { mcpmBinary: "mcpm" },
    );
    // Attacker rewrites the original command after the `--` separator.
    const sepIdx = wrapped.args!.indexOf("--");
    const tampered = {
      ...wrapped,
      args: wrapped.args!.map((a, i) => (i === sepIdx + 1 ? "rm" : a)),
    };
    expect(isWrapped(tampered)).toBe(true); // marker still detected
    expect(unwrapEntry(tampered)).toBeNull(); // but hash mismatch → refuse
  });

  test("refuses to unwrap when a wrapped arg is tampered", () => {
    const wrapped = wrapEntry(
      "victim",
      { command: "node", args: ["/safe/server.js"] },
      { mcpmBinary: "mcpm" },
    );
    const sepIdx = wrapped.args!.indexOf("--");
    const tampered = {
      ...wrapped,
      args: wrapped.args!.map((a, i) => (i === sepIdx + 2 ? "/attacker/evil.js" : a)),
    };
    expect(unwrapEntry(tampered)).toBeNull();
  });

  test("accepts an untampered wrap (hash matches)", () => {
    const orig = { command: "npx", args: ["-y", "@org/x"], env: { K: "v" } };
    const wrapped = wrapEntry("ok", orig, { mcpmBinary: "mcpm" });
    expect(unwrapEntry(wrapped)).toEqual(orig);
  });

  test("refuses to unwrap a marker that carries no --orig-hash (strip-bypass)", () => {
    // Fail closed: an entry with no hash flag cannot be integrity-verified. An
    // attacker stripping the flag (or a genuinely pre-hash legacy entry) must
    // NOT skip verification — unwrap refuses and the caller falls back to .bak.
    const noHash = {
      command: "mcpm",
      args: ["guard", "run", "--inner", "--server-name", "old", "--", "npx", "-y", "x"],
    };
    expect(unwrapEntry(noHash)).toBeNull();
  });

  test("refuses to unwrap when the --orig-hash pair is removed from a valid wrap", () => {
    const wrapped = wrapEntry(
      "victim",
      { command: "npx", args: ["-y", "@org/good"] },
      { mcpmBinary: "mcpm" },
    );
    // Attacker strips the `--orig-hash <hex>` pair, leaving an otherwise valid
    // marker that reconstructs the real command — verification must not be
    // silently skipped.
    const hashIdx = wrapped.args!.indexOf(WRAP_ORIG_HASH_FLAG);
    const stripped = {
      ...wrapped,
      args: [...wrapped.args!.slice(0, hashIdx), ...wrapped.args!.slice(hashIdx + 2)],
    };
    expect(isWrapped(stripped)).toBe(true); // marker still detected
    expect(unwrapEntry(stripped)).toBeNull(); // but no hash → refuse
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

// ─────────────── F1: confine marker tokens (produce / parse / neutrality) ───────────────

const HEX64 = "a".repeat(64);

describe("wrapEntry — confine marker tokens", () => {
  test("emits --confine-profile-hash + --confine-required before `--`, after --orig-hash", () => {
    const wrapped = wrapEntry(
      "fs",
      { command: "npx", args: ["-y", "srv"], env: { FOO: "1" } },
      ctx,
      { profileHash: HEX64, required: true },
    );
    const a = wrapped.args!;
    const iHash = a.indexOf(WRAP_CONFINE_HASH_FLAG);
    const iReq = a.indexOf(WRAP_CONFINE_REQUIRED_FLAG);
    const iSep = a.indexOf(WRAP_ARG_SEPARATOR);
    const iOrig = a.indexOf(WRAP_ORIG_HASH_FLAG);
    expect(iHash).toBeGreaterThan(iOrig); // confine tokens follow --orig-hash
    expect(a[iHash + 1]).toBe(HEX64);
    expect(iReq).toBeGreaterThan(-1);
    expect(iHash).toBeLessThan(iSep); // ...and both precede `--`
    expect(iReq).toBeLessThan(iSep);
  });

  test("omits --confine-required when required=false", () => {
    const wrapped = wrapEntry("fs", { command: "x" }, ctx, { profileHash: HEX64, required: false });
    expect(wrapped.args).toContain(WRAP_CONFINE_HASH_FLAG);
    expect(wrapped.args).not.toContain(WRAP_CONFINE_REQUIRED_FLAG);
  });

  test("no confine arg → no confine tokens (unchanged wraps)", () => {
    const wrapped = wrapEntry("fs", { command: "x" }, ctx);
    expect(wrapped.args).not.toContain(WRAP_CONFINE_HASH_FLAG);
    expect(wrapped.args).not.toContain(WRAP_CONFINE_REQUIRED_FLAG);
  });
});

describe("confine marker NEUTRALITY (orig-hash + unwrap unaffected)", () => {
  const orig = { command: "npx", args: ["-y", "srv", "/data"], env: { API_KEY: "x", B: "y" } };

  test("unwrapEntry still verifies orig-hash and reconstructs the original entry", () => {
    const wrapped = wrapEntry("fs", orig, ctx, { profileHash: HEX64, required: true });
    const back = unwrapEntry(wrapped);
    expect(back).not.toBeNull();
    expect(back!.command).toBe("npx");
    expect(back!.args).toEqual(["-y", "srv", "/data"]);
    expect(back!.env).toEqual({ API_KEY: "x", B: "y" });
  });

  test("isWrapped works with confine tokens present", () => {
    const wrapped = wrapEntry("fs", orig, ctx, { profileHash: HEX64, required: false });
    expect(isWrapped(wrapped)).toBe(true);
  });

  test("a wrapped-with-confine entry's --orig-hash equals the confine-free hash (excluded from hash)", () => {
    const withConfine = wrapEntry("fs", orig, ctx, { profileHash: HEX64, required: true });
    const a = withConfine.args!;
    expect(a[a.indexOf(WRAP_ORIG_HASH_FLAG) + 1]).toBe(
      hashOriginalEntry("npx", ["-y", "srv", "/data"], ["API_KEY", "B"]),
    );
  });

  test("wrapEntry refuses to embed a non-64-hex confine hash (write-side guard)", () => {
    expect(() => wrapEntry("fs", orig, ctx, { profileHash: "not-hex", required: false })).toThrow(
      /64/,
    );
  });

  test("a hand-crafted marker with a bad confine hash → parseMarker rejects → unwrap refuses", () => {
    // Simulate an attacker hand-editing the IDE config to a malformed hash.
    const good = wrapEntry("fs", orig, ctx, { profileHash: HEX64, required: false });
    const tampered = { ...good, args: good.args!.map((a) => (a === HEX64 ? "deadbeef" : a)) };
    expect(unwrapEntry(tampered)).toBeNull();
  });
});
