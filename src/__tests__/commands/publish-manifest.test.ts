/**
 * Tests for src/commands/publish/manifest.ts
 * Covers: ENOENT returns null, valid YAML parsed, invalid YAML throws,
 * non-ENOENT fs error rethrows.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readManifest, validateDescription } from "../../commands/publish/manifest.js";

vi.mock("node:fs/promises");
vi.mock("../../utils/fs.js");

const { readFile } = await import("node:fs/promises");
const { isEnoent } = await import("../../utils/fs.js");

const mockReadFile = vi.mocked(readFile);
const mockIsEnoent = vi.mocked(isEnoent);

const VALID_YAML = `
name: io.github.test/my-server
description: A test MCP server
homepage: https://github.com/test/my-server
tags: [test]
package:
  registryType: npm
  identifier: "@test/my-server"
`.trim();

describe("readManifest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsEnoent.mockReturnValue(false);
  });

  it("returns null when manifest file does not exist", async () => {
    const notFound = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockReadFile.mockRejectedValue(notFound);
    mockIsEnoent.mockReturnValue(true);

    const result = await readManifest("/fake/cwd");
    expect(result).toBeNull();
  });

  it("parses and returns a valid manifest", async () => {
    mockReadFile.mockResolvedValue(VALID_YAML);

    const result = await readManifest("/fake/cwd");
    expect(result).toMatchObject({
      name: "io.github.test/my-server",
      description: "A test MCP server",
      package: { registryType: "npm", identifier: "@test/my-server" },
    });
  });

  it("throws a user-friendly error for invalid YAML content", async () => {
    mockReadFile.mockResolvedValue("name: \ndescription: \npackage: bad");

    await expect(readManifest("/fake/cwd")).rejects.toThrow("Invalid .mcpm-publish.yaml");
  });

  // backlog #85: the registry's server.schema.json caps `description` at 100
  // chars (confirmed against static.modelcontextprotocol.io); mcpm's own
  // manifest schema only checked min(1), so an over-cap description passed
  // `mcpm publish check` and was rejected by the registry at submit time.
  it("rejects a description over 100 characters, naming the cap and the actual length", async () => {
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", "a".repeat(101)));

    await expect(readManifest("/fake/cwd")).rejects.toThrow(
      /caps description at 100 characters.*yours is 101/s
    );
  });

  it("accepts a description of exactly 100 characters", async () => {
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", "a".repeat(100)));

    const result = await readManifest("/fake/cwd");
    expect(result?.description).toHaveLength(100);
  });

  // The cap is CODE POINTS on both sides: draft-07 maxLength counts RFC 8259
  // characters and the registry measures with utf8.RuneCount, so an emoji is
  // one character to the registry and two to `String.length`. Every ASCII case
  // above passes either way — these two are the only ones that can tell the
  // units apart.
  it("accepts 100 emoji (100 code points, 200 UTF-16 units) — the registry does", async () => {
    const description = "\u{1F389}".repeat(100);
    expect(description.length).toBe(200);
    expect([...description].length).toBe(100);
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", description));

    const result = await readManifest("/fake/cwd");
    expect([...(result?.description ?? "")]).toHaveLength(100);
  });

  it("reports the over-cap length in code points, not UTF-16 units", async () => {
    const description = "\u{1F389}".repeat(101);
    expect(description.length).toBe(202);
    expect([...description].length).toBe(101);
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", description));

    const err = await readManifest("/fake/cwd").catch((e: Error) => e);
    expect((err as Error).message).toContain("yours is 101");
    expect((err as Error).message).not.toContain("yours is 202");
  });

  // The formatted "path: message" list is the half of #85 that a `.parse()`
  // revert would silently undo: the raw ZodError dump EMBEDS the same custom
  // message, so any assertion that only looks for the message text passes
  // against both. These assert the framing instead.
  it("formats issues as a path-prefixed list, not a raw ZodError JSON dump", async () => {
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", "a".repeat(101)));

    const err = (await readManifest("/fake/cwd").catch((e: Error) => e)) as Error;
    expect(err.message).toContain("Invalid .mcpm-publish.yaml:\n  description: ");
    expect(err.message).not.toMatch(/"code":\s*"too_big"/);
  });

  it("names every failing field when more than one is invalid", async () => {
    mockReadFile.mockResolvedValue("name: \"\"\ndescription: ok\npackage:\n  registryType: npm\n  identifier: \"\"\n");

    const err = (await readManifest("/fake/cwd").catch((e: Error) => e)) as Error;
    expect(err.message).toContain("\n  name: ");
    expect(err.message).toContain("\n  package.identifier: ");
  });

  it("rethrows non-ENOENT fs errors", async () => {
    const permError = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockReadFile.mockRejectedValue(permError);
    mockIsEnoent.mockReturnValue(false);

    await expect(readManifest("/fake/cwd")).rejects.toThrow("EACCES");
  });
});

// ---------------------------------------------------------------------------
// The scaffold wizard's description check (shared with the schema above)
// ---------------------------------------------------------------------------

describe("validateDescription", () => {
  it("accepts a description at the cap", () => {
    expect(validateDescription("a".repeat(100))).toBe(true);
  });

  it("accepts 51 emoji — 51 characters to the registry, 102 UTF-16 units", () => {
    const description = "\u{1F389}".repeat(51);
    expect(description.length).toBe(102);
    expect(validateDescription(description)).toBe(true);
  });

  it("rejects an over-cap description with the same message the manifest reader gives", async () => {
    mockReadFile.mockResolvedValue(VALID_YAML.replace("A test MCP server", "a".repeat(101)));
    const fromReader = (await readManifest("/fake/cwd").catch((e: Error) => e)) as Error;

    expect(validateDescription("a".repeat(101))).toBe(
      "the MCP registry caps description at 100 characters (server.schema.json maxLength); yours is 101"
    );
    expect(fromReader.message).toContain(validateDescription("a".repeat(101)) as string);
  });
});
