/**
 * Tests for src/registry/argument-tokens.ts — written FIRST per TDD.
 *
 * argumentTokens is the single shared extractor of security-relevant string
 * tokens from an Argument. It must be TOTAL over string | named | positional |
 * unknown-future, never mutate input, and always return a (possibly empty) array.
 */

import { describe, it, expect } from "vitest";
import { argumentTokens, type RuntimeArgument } from "./argument-tokens.js";

describe("argumentTokens", () => {
  it("string arg -> [s]", () => {
    expect(argumentTokens("--verbose")).toEqual(["--verbose"]);
  });

  it("named arg (name only) -> [name]", () => {
    expect(argumentTokens({ type: "named", name: "--rm" })).toEqual(["--rm"]);
  });

  it("positional arg with value -> [value]", () => {
    expect(argumentTokens({ type: "positional", value: "-y" })).toEqual(["-y"]);
  });

  it("named arg with value -> [name, value] in order", () => {
    expect(argumentTokens({ type: "named", name: "--port", value: "8089" })).toEqual([
      "--port",
      "8089",
    ]);
  });

  it("positional placeholder (valueHint only) -> [valueHint]", () => {
    expect(
      argumentTokens({ type: "positional", valueHint: "directory" })
    ).toEqual(["directory"]);
  });

  it("empty object -> []", () => {
    expect(argumentTokens({})).toEqual([]);
  });

  it("unknown future shape -> [] (totality, no throw)", () => {
    expect(argumentTokens({ type: "edn" } as RuntimeArgument)).toEqual([]);
  });

  it("never mutates the input object", () => {
    const arg: RuntimeArgument = { type: "named", name: "--port", value: "8089" };
    const snapshot = JSON.parse(JSON.stringify(arg));
    argumentTokens(arg);
    expect(arg).toEqual(snapshot);
  });

  it("returns a new array on each call", () => {
    const arg: RuntimeArgument = { type: "named", name: "--rm" };
    expect(argumentTokens(arg)).not.toBe(argumentTokens(arg));
  });
});
