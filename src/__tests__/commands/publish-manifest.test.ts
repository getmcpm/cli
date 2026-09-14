/**
 * Tests for src/commands/publish/manifest.ts
 * Covers: ENOENT returns null, valid YAML parsed, invalid YAML throws,
 * non-ENOENT fs error rethrows.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  readManifest,
  validateDescription,
  manifestToServerJson,
  resolveVersion,
  PublishManifestSchema,
  SERVER_SCHEMA_URL,
  type PublishManifest,
} from "../../commands/publish/manifest.js";

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

// ---------------------------------------------------------------------------
// manifestToServerJson — the exact body POSTed to /v0.1/publish and
// /v0.1/validate. Shapes pinned here were confirmed live against
// registry.modelcontextprotocol.io on 2026-09-14: mutating any of `$schema`,
// `packages[].transport`, the runtimeArguments Argument shape, or the
// repository `source` (not `type`) field must fail these.
// ---------------------------------------------------------------------------

const BASE_RAW = {
  name: "io.github.test/my-server",
  description: "A test MCP server",
  package: { registryType: "npm" as const, identifier: "@test/my-server" },
};

const BASE: PublishManifest = PublishManifestSchema.parse(BASE_RAW);

describe("manifestToServerJson", () => {
  it("sets $schema and the ServerJSON-required keys (name, description, version)", () => {
    const result = manifestToServerJson(BASE, "1.2.3");
    expect(result.$schema).toBe(SERVER_SCHEMA_URL);
    expect(result).toMatchObject({
      name: "io.github.test/my-server",
      description: "A test MCP server",
      version: "1.2.3",
    });
  });

  it("packages[0].transport defaults to stdio when the manifest omits transport", () => {
    const result = manifestToServerJson(BASE, "1.0.0");
    expect(result.packages).toHaveLength(1);
    expect(result.packages[0].transport).toEqual({ type: "stdio" });
  });

  it("packages[0].version matches the resolved version, not a placeholder", () => {
    const result = manifestToServerJson(BASE, "9.9.9");
    expect(result.packages[0].version).toBe("9.9.9");
    expect(result.packages[0].registryType).toBe("npm");
    expect(result.packages[0].identifier).toBe("@test/my-server");
  });

  it("maps the runtimeArguments string shorthand to registry positional Argument objects", () => {
    const manifest = PublishManifestSchema.parse({ ...BASE_RAW, runtimeArguments: ["serve"] });
    const result = manifestToServerJson(manifest, "1.0.0");
    expect(result.packages[0].runtimeArguments).toEqual([{ type: "positional", value: "serve" }]);
  });

  it("omits runtimeArguments/runtimeHint/environmentVariables entirely when not set (no empty arrays)", () => {
    const result = manifestToServerJson(BASE, "1.0.0");
    expect(result.packages[0]).not.toHaveProperty("runtimeArguments");
    expect(result.packages[0]).not.toHaveProperty("runtimeHint");
    expect(result.packages[0]).not.toHaveProperty("environmentVariables");
  });

  it("maps repository as {source, url} — the registry's Repository schema has no `type` field", () => {
    const manifest = PublishManifestSchema.parse({
      ...BASE_RAW,
      repository: { source: "github", url: "https://github.com/test/my-server" },
    });
    const result = manifestToServerJson(manifest, "1.0.0");
    expect(result.repository).toEqual({ source: "github", url: "https://github.com/test/my-server" });
    expect(result.repository).not.toHaveProperty("type");
  });

  it("uses homepage as websiteUrl when websiteUrl is not explicitly set", () => {
    const manifest = PublishManifestSchema.parse({ ...BASE_RAW, homepage: "https://example.com" });
    const result = manifestToServerJson(manifest, "1.0.0");
    expect(result.websiteUrl).toBe("https://example.com");
  });

  it("prefers an explicit websiteUrl over homepage", () => {
    const manifest = PublishManifestSchema.parse({
      ...BASE_RAW,
      homepage: "https://example.com/homepage",
      websiteUrl: "https://example.com/site",
    });
    const result = manifestToServerJson(manifest, "1.0.0");
    expect(result.websiteUrl).toBe("https://example.com/site");
  });

  it("passes environmentVariables through unchanged (already registry-shaped)", () => {
    const manifest = PublishManifestSchema.parse({
      ...BASE_RAW,
      environmentVariables: [{ name: "API_KEY", isRequired: true, isSecret: true }],
    });
    const result = manifestToServerJson(manifest, "1.0.0");
    expect(result.packages[0].environmentVariables).toEqual([
      { name: "API_KEY", isRequired: true, isSecret: true },
    ]);
  });
});

// ---------------------------------------------------------------------------
// resolveVersion — manifest.version → package.json in cwd → error.
// ---------------------------------------------------------------------------

describe("resolveVersion", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockIsEnoent.mockReturnValue(false);
  });

  it("uses the manifest's own version when set, without reading package.json", async () => {
    const manifest = PublishManifestSchema.parse({ ...BASE_RAW, version: "9.9.9" });
    const version = await resolveVersion(manifest, "/fake/cwd");
    expect(version).toBe("9.9.9");
    expect(mockReadFile).not.toHaveBeenCalled();
  });

  it("falls back to package.json's version in cwd when the manifest omits version", async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ version: "2.3.4" }));
    const version = await resolveVersion(BASE, "/fake/cwd");
    expect(version).toBe("2.3.4");
    expect(mockReadFile).toHaveBeenCalledWith(expect.stringContaining("package.json"), "utf-8");
  });

  it("throws a clear error when neither the manifest nor a package.json has a version (ENOENT)", async () => {
    const notFound = Object.assign(new Error("ENOENT"), { code: "ENOENT" });
    mockReadFile.mockRejectedValue(notFound);
    mockIsEnoent.mockReturnValue(true);
    await expect(resolveVersion(BASE, "/fake/cwd")).rejects.toThrow(/No version found/);
  });

  it("throws when package.json exists but has no version field", async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ name: "x" }));
    await expect(resolveVersion(BASE, "/fake/cwd")).rejects.toThrow(/No version found/);
  });

  it("rethrows non-ENOENT fs errors reading package.json", async () => {
    const permError = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockReadFile.mockRejectedValue(permError);
    mockIsEnoent.mockReturnValue(false);
    await expect(resolveVersion(BASE, "/fake/cwd")).rejects.toThrow("EACCES");
  });
});
