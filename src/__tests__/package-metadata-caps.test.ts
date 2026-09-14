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
 *   on `description`. The old hand-submission template
 *   `docs/registry-entry.json` (no code read it) exceeded it by 278; it was
 *   deleted in favor of the root `.mcpm-publish.yaml`, the manifest
 *   `mcpm publish` actually reads and sends (#216) —
 *   `PublishManifestSchema` already enforces `max(100)` at read time
 *   (backlog #85, publish-manifest.test.ts), so this test is redundant with
 *   that runtime check for THIS file specifically. Kept anyway as a static,
 *   code-free tripwire that needs no test harness to run.
 *
 * Neither cap is enforced by `npm pack`, `tsc` or CI, so a future SEO edit
 * would repeat it unseen until the next publish. This pins both.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import { describe, expect, it } from "vitest";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const readJson = (rel: string): { description: string } =>
  JSON.parse(readFileSync(join(rootDir, rel), "utf8")) as { description: string };
const readYaml = (rel: string): { description: string } =>
  parseYaml(readFileSync(join(rootDir, rel), "utf8")) as { description: string };

// npm registry metadata cap, measured on the v0.39.1 listing (#208).
const NPM_DESCRIPTION_CAP = 255;
// `maxLength` on `description` in server.schema.json (2025-12-11).
const MCP_REGISTRY_DESCRIPTION_CAP = 100;

describe("listing-metadata description caps", () => {
  it("package.json description survives npm's 255-char metadata cap", () => {
    expect(readJson("package.json").description.length).toBeLessThanOrEqual(NPM_DESCRIPTION_CAP);
  });

  it(".mcpm-publish.yaml description fits the MCP Registry schema maxLength", () => {
    expect([...readYaml(".mcpm-publish.yaml").description].length).toBeLessThanOrEqual(
      MCP_REGISTRY_DESCRIPTION_CAP,
    );
  });
});
