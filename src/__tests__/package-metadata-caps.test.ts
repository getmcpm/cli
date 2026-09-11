/**
 * Listing-metadata length caps.
 *
 * Two registries silently accept a `description` longer than they will show
 * or admit, and both bit this repo in the same week:
 *
 * - npm truncates registry metadata at 255 characters. The 275-char string
 *   PR #207 shipped in v0.39.1 published fine, but `npm view` and the
 *   npmjs.com listing rendered "... VS Code, Win" (#208).
 * - The official MCP Registry's `server.schema.json` sets `maxLength: 100`
 *   on `description`, which `docs/registry-entry.json` exceeded by 278.
 *
 * Neither cap is enforced by `npm pack`, `tsc` or CI, so a future SEO edit
 * would repeat it unseen until the next publish. This pins both.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const readJson = (rel: string): { description: string } =>
  JSON.parse(readFileSync(join(rootDir, rel), "utf8")) as { description: string };

// npm registry metadata cap, measured on the v0.39.1 listing (#208).
const NPM_DESCRIPTION_CAP = 255;
// `maxLength` on `description` in server.schema.json (2025-12-11).
const MCP_REGISTRY_DESCRIPTION_CAP = 100;

describe("listing-metadata description caps", () => {
  it("package.json description survives npm's 255-char metadata cap", () => {
    expect(readJson("package.json").description.length).toBeLessThanOrEqual(NPM_DESCRIPTION_CAP);
  });

  it("docs/registry-entry.json description fits the MCP Registry schema maxLength", () => {
    expect(readJson("docs/registry-entry.json").description.length).toBeLessThanOrEqual(
      MCP_REGISTRY_DESCRIPTION_CAP,
    );
  });
});
