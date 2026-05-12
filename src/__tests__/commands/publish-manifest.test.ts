/**
 * Tests for src/commands/publish/manifest.ts
 * Covers: ENOENT returns null, valid YAML parsed, invalid YAML throws,
 * non-ENOENT fs error rethrows.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { readManifest } from "../../commands/publish/manifest.js";

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

  it("rethrows non-ENOENT fs errors", async () => {
    const permError = Object.assign(new Error("EACCES"), { code: "EACCES" });
    mockReadFile.mockRejectedValue(permError);
    mockIsEnoent.mockReturnValue(false);

    await expect(readManifest("/fake/cwd")).rejects.toThrow("EACCES");
  });
});
