/**
 * Tests for src/server/tools.ts — MCP tool input schema hardening (security #31).
 *
 * The Zod layer is the declarative enforcement point: bounded strings, an enum
 * for `client`, and strict objects (unknown keys rejected, not silently dropped).
 * These schemas reach the MCP SDK via `.shape`, so each test also confirms the
 * per-field schemas — the part that actually propagates through `.shape` — stay
 * intact for SDK registration.
 */

import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  SearchInput,
  InstallInput,
  InfoInput,
  ListInput,
  RemoveInput,
  SetupInput,
  UpInput,
} from "../../server/tools.js";
import { CLIENT_IDS } from "../../config/paths.js";

const VALID_NAME = "io.github.domdomegg/filesystem-mcp";
// Source of truth — newly added clients are covered automatically.
const VALID_CLIENTS = CLIENT_IDS;

describe("InstallInput (security #31)", () => {
  it("accepts a valid server name", () => {
    expect(InstallInput.safeParse({ name: VALID_NAME }).success).toBe(true);
  });

  it("rejects an empty name", () => {
    expect(InstallInput.safeParse({ name: "" }).success).toBe(false);
  });

  it("accepts a name at the 256-char bound and rejects one past it", () => {
    expect(InstallInput.safeParse({ name: "a".repeat(256) }).success).toBe(true);
    expect(InstallInput.safeParse({ name: "a".repeat(257) }).success).toBe(false);
  });

  it.each(VALID_CLIENTS)("accepts known client %s", (client) => {
    expect(InstallInput.safeParse({ name: VALID_NAME, client }).success).toBe(true);
  });

  it("rejects an unknown client", () => {
    expect(InstallInput.safeParse({ name: VALID_NAME, client: "emacs" }).success).toBe(false);
  });

  it("treats client as optional", () => {
    expect(InstallInput.safeParse({ name: VALID_NAME }).success).toBe(true);
  });

  it("rejects unknown keys (strict)", () => {
    expect(
      InstallInput.safeParse({ name: VALID_NAME, unexpectedKey: 1 }).success
    ).toBe(false);
  });

  it("defaults minTrustScore to 50", () => {
    const parsed = InstallInput.parse({ name: VALID_NAME });
    expect(parsed.minTrustScore).toBe(50);
  });

  it("rejects minTrustScore out of range", () => {
    expect(InstallInput.safeParse({ name: VALID_NAME, minTrustScore: 101 }).success).toBe(false);
  });
});

describe("InfoInput (security #31)", () => {
  it("bounds the name and rejects overflow", () => {
    expect(InfoInput.safeParse({ name: VALID_NAME }).success).toBe(true);
    expect(InfoInput.safeParse({ name: "a".repeat(257) }).success).toBe(false);
    expect(InfoInput.safeParse({ name: "" }).success).toBe(false);
  });

  it("rejects unknown keys (strict)", () => {
    expect(InfoInput.safeParse({ name: VALID_NAME, extra: true }).success).toBe(false);
  });
});

describe("ListInput (security #31)", () => {
  it("accepts a known client and treats it as optional", () => {
    expect(ListInput.safeParse({}).success).toBe(true);
    expect(ListInput.safeParse({ client: "cursor" }).success).toBe(true);
  });

  it("rejects an unknown client", () => {
    expect(ListInput.safeParse({ client: "notARealClient" }).success).toBe(false);
  });

  it("rejects unknown keys (strict)", () => {
    expect(ListInput.safeParse({ client: "cursor", bogus: 1 }).success).toBe(false);
  });
});

describe("RemoveInput (security #31)", () => {
  it("bounds the name and enforces the client enum", () => {
    expect(RemoveInput.safeParse({ name: VALID_NAME, client: "vscode" }).success).toBe(true);
    expect(RemoveInput.safeParse({ name: "a".repeat(257) }).success).toBe(false);
    expect(RemoveInput.safeParse({ name: VALID_NAME, client: "nano" }).success).toBe(false);
  });

  it("rejects unknown keys (strict)", () => {
    expect(RemoveInput.safeParse({ name: VALID_NAME, surprise: "x" }).success).toBe(false);
  });
});

describe("SearchInput / SetupInput / UpInput stay strict (security #31)", () => {
  it("SearchInput rejects unknown keys but keeps existing bounds", () => {
    expect(SearchInput.safeParse({ query: "fs" }).success).toBe(true);
    expect(SearchInput.safeParse({ query: "" }).success).toBe(false);
    expect(SearchInput.safeParse({ query: "fs", junk: 1 }).success).toBe(false);
  });

  it("SetupInput enforces the client enum and rejects unknown keys", () => {
    expect(SetupInput.safeParse({ description: "filesystem", client: "cursor" }).success).toBe(true);
    expect(SetupInput.safeParse({ description: "filesystem", client: "atom" }).success).toBe(false);
    expect(SetupInput.safeParse({ description: "fs", junk: true }).success).toBe(false);
  });

  it("UpInput rejects unknown keys", () => {
    expect(UpInput.safeParse({}).success).toBe(true);
    expect(UpInput.safeParse({ unexpected: 1 }).success).toBe(false);
  });
});

describe(".shape stays usable for MCP SDK registration (security #31)", () => {
  it("exposes per-field schemas that validate a real payload via z.object(shape)", () => {
    // The SDK rebuilds z.object(InstallInput.shape); the bounded fields + client
    // enum must survive that path (the strict() object setting does not, which is
    // why the bounds live on the fields).
    const rebuilt = z.object(InstallInput.shape);
    expect(rebuilt.safeParse({ name: VALID_NAME, client: "cursor" }).success).toBe(true);
    expect(rebuilt.safeParse({ name: VALID_NAME, client: "emacs" }).success).toBe(false);
    expect(rebuilt.safeParse({ name: "a".repeat(257) }).success).toBe(false);
  });
});
