/**
 * `server.json` ↔ `package.json` ↔ release-automation invariant.
 *
 * mcpm publishes itself to the official MCP Registry as `io.github.getmcpm/cli`.
 * That listing was created by hand on 2026-03-30 and then never touched again.
 * By 2026-08-17 it still advertised `version: "0.1.3"` with
 * `packages[0].version: "0.1.3"` and `isLatest: true`, while npm's `latest`
 * dist-tag served **0.30.0** — 43 published versions and four and a half months
 * of drift.
 *
 * That was not merely cosmetic. The pinned 0.1.3 tarball still contains the
 * tier-2 scanner probe against the UNREGISTERED `@invariantlabs` npm scope: the
 * fetch-and-execute-on-every-`mcpm audit` supply-chain vector disclosed and
 * closed in v0.28.0. So the registry entry for a package manager whose pitch is
 * supply-chain hygiene was a live pointer at its own known-vulnerable build.
 * (It also predates the guard relay, --confine, Sigstore verification and the
 * response-side DLP — every security feature the README leads with.)
 *
 * The root cause was mechanical, and worth stating precisely because it looks
 * like mere neglect and was not: `server.json` was listed in `.gitignore` from
 * #141 (2026-07-23) under the heading "MCP Registry publisher" — almost
 * certainly to hide the scratch file `mcp-publisher init` drops in the working
 * tree. The effect was that the one file the release pipeline would need could
 * not be committed, so the listing was structurally condemned to be published by
 * hand, and no workflow could have referenced it. Nothing pointed at it either:
 * the repo's only manifest was `docs/registry-entry.json`, a
 * submission artifact that had itself gone stale at `version: "0.5.0"`, had
 * drifted from the published schema (no `packages[].version`, no `transport`, a
 * `runtimeArguments: ["serve"]` shape the schema no longer accepts, and a
 * description over the 100-character limit), and was referenced by nothing.
 * Three sources of truth — repo, listing, npm — telling three different stories.
 *
 * So these are DRIFT guards, and they check the automation as well as the file.
 * The version assertions deliberately do NOT compare against `package.json`'s
 * `version` field: that is frozen at 0.15.0 on purpose (CI derives the real
 * version from the git tag), so requiring equality would encode the opposite of
 * how this repo releases. What CAN be pinned is internal coherence, the schema
 * limits that would otherwise only fail at tag time, and — the load-bearing one
 * — that the stamping script actually moves BOTH version fields.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { stampServerJson } from "../../scripts/stamp-server-json.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const serverJson = JSON.parse(readFileSync(join(REPO_ROOT, "server.json"), "utf8"));
const packageJson = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf8"));

describe("server.json ↔ package.json identity", () => {
  it("declares the same server name that package.json claims via mcpName", () => {
    // The registry proves npm-package ownership by reading `mcpName` out of the
    // published package and requiring it to equal the listing's `name`. If these
    // two drift apart the publish is rejected — at tag time, after npm has
    // already gone out.
    expect(serverJson.name).toBe(packageJson.mcpName);
  });

  it("pins the npm package that this repo actually publishes", () => {
    const npmPackages = serverJson.packages.filter(
      (p: { registryType: string }) => p.registryType === "npm",
    );
    expect(npmPackages).toHaveLength(1);
    expect(npmPackages[0].identifier).toBe(packageJson.name);
  });

  it("points at the same repository as package.json", () => {
    // Compare canonicalized: package.json's url has no `git+` prefix or `.git`
    // suffix, npm normalizes it on publish, and the registry wants the browsable
    // form. Normalize both rather than asserting one spelling.
    const canonical = (url: string) => url.replace(/^git\+/, "").replace(/\.git$/, "");
    expect(canonical(serverJson.repository.url)).toBe(canonical(packageJson.repository.url));
  });

  it("carries the immutable numeric GitHub repository id", () => {
    // The registry uses the forge-assigned id to detect repository-resurrection
    // attacks: delete `getmcpm/cli` and recreate it and the id changes, while the
    // URL does not. mcpm's own provenance tripwire keys off the same immutable
    // ids (v0.22.0), so omitting it here would be inconsistent with what mcpm
    // demands of the servers it scores.
    expect(serverJson.repository.id).toMatch(/^\d+$/);
  });
});

describe("server.json schema limits that would otherwise fail at tag time", () => {
  it("keeps description within the schema's 100-character maximum", () => {
    // `ServerDetail.description` is `maxLength: 100`. A well-meaning expansion
    // to cover more features is the obvious way to break this, and without a
    // guard it surfaces only when `mcp-publisher publish` rejects it — after the
    // npm release has shipped.
    expect(serverJson.description.length).toBeGreaterThan(0);
    expect(serverJson.description.length).toBeLessThanOrEqual(100);
  });

  it("pins a dated schema revision rather than a floating one", () => {
    expect(serverJson.$schema).toMatch(
      /^https:\/\/static\.modelcontextprotocol\.io\/schemas\/\d{4}-\d{2}-\d{2}\/server\.schema\.json$/,
    );
  });

  it("declares a concrete package version, never a range or dist-tag", () => {
    for (const pkg of serverJson.packages) {
      expect(pkg.version).toMatch(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/);
    }
  });

  it("declares a transport and a runtime hint for its runtime arguments", () => {
    for (const pkg of serverJson.packages) {
      expect(pkg.transport?.type).toBe("stdio");
      // The schema asks for `runtimeHint` whenever `runtimeArguments` are
      // present, so a client knows the args belong to npx rather than the binary.
      if (pkg.runtimeArguments?.length) expect(pkg.runtimeHint).toBeTruthy();
    }
  });

  it("agrees with itself: server version equals every package version", () => {
    for (const pkg of serverJson.packages) {
      expect(pkg.version).toBe(serverJson.version);
    }
  });
});

describe("release automation stamps the listing", () => {
  const withTempManifest = (fn: (path: string) => void) => {
    const dir = mkdtempSync(join(tmpdir(), "mcpm-server-json-"));
    const path = join(dir, "server.json");
    writeFileSync(path, readFileSync(join(REPO_ROOT, "server.json"), "utf8"));
    fn(path);
  };

  it("moves BOTH the server version and every package version", () => {
    // THE anti-recurrence guard. The upstream docs' suggested one-liner
    // (`jq '.version = $v'`) stamps only the top-level field, which publishes a
    // listing that advertises the new release while pinning clients to the old
    // tarball. Executing the real script — rather than grepping the workflow for
    // a jq expression — is what makes this test able to fail on a wrong
    // expression instead of merely a missing one.
    withTempManifest((path) => {
      stampServerJson("9.9.9", path);
      const stamped = JSON.parse(readFileSync(path, "utf8"));
      expect(stamped.version).toBe("9.9.9");
      expect(stamped.packages.length).toBeGreaterThan(0);
      for (const pkg of stamped.packages) {
        expect(pkg.version).toBe("9.9.9");
      }
    });
  });

  it("refuses a version range or dist-tag", () => {
    // A bad tag should fail on the line that produced it, not silently publish a
    // listing the registry will reject.
    withTempManifest((path) => {
      for (const bad of ["^1.2.3", "1.x", "latest", "v1.2.3", ""]) {
        expect(() => stampServerJson(bad, path)).toThrow(/non-concrete version/);
      }
    });
  });

  it("is invoked by the publish workflow", () => {
    // The listing drifted for 43 releases precisely because no workflow touched
    // it. Assert the wiring exists, so deleting the step reddens CI.
    const workflow = readFileSync(join(REPO_ROOT, ".github/workflows/publish.yml"), "utf8");
    expect(workflow).toContain("scripts/stamp-server-json.mjs");
    expect(workflow).toContain("mcp-publisher publish");
  });
});
