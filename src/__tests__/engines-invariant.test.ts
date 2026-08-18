/**
 * `engines.node` ↔ dependency-engines invariant.
 *
 * `package.json`'s `engines.node` is a PROMISE to the user: install mcpm on a
 * Node in this range and it works. npm checks that promise against every
 * package in the install tree and prints `EBADENGINE` for each one whose own
 * range the running Node falls outside — and with `engine-strict=true` (common
 * in corporate .npmrc) the install FAILS instead of warning.
 *
 * That promise was false. By v0.29.0 the declaration was `>=22.9.0` while four
 * direct runtime deps required more — @sigstore/bundle and @sigstore/verify
 * (`^22.22.2 || ^24.15.0 || >=26.0.0`), @inquirer/prompts
 * (`>=23.5.0 || ^22.13.0 || ^20.17.0`) and commander (`>=22.12.0`) — 20
 * packages across the transitive closure. Every user on Node 22.9–22.22.1,
 * 24.0–24.14, 23.x or 25.x got EBADENGINE warnings on install, from a package
 * manager whose pitch is supply-chain hygiene.
 *
 * The drift was NOT a dependency moving out from under a correct declaration.
 * `>=22.9.0` was set in v0.23.0 (7e27973, 2026-07-20) to match @sigstore/bundle@4,
 * but that same commit's lockfile already carried commander@15 (`>=22.12.0`) and
 * @inquirer/prompts@8.5.2 (`>=23.5.0 || ^22.13.0 || ^20.17.0`), so the
 * declaration was contradicted the moment it was written. The
 * @sigstore/bundle@4→@5 bump five days later (215680e) widened the gap —
 * raising the 22.x floor to 22.22.2 and newly excluding 23.x, 24.0–24.14 and
 * 25.x — it did not create it.
 *
 * CI could not catch it: the matrix is `[22, 24, 26]` and `setup-node` resolves
 * the LATEST minor of each major, which satisfies the dep ranges. The declared
 * FLOOR is never the Node that runs. So this test checks the declaration
 * against the dependency tree directly, independent of the Node executing it —
 * the same failure shape as the tier-2 scanner in v0.28.0, where the tests
 * covered the code but never the dependency the code named.
 *
 * Scope is the full transitive RUNTIME closure (`dependencies` +
 * `optionalDependencies`), because that is exactly the set npm warns about.
 * devDependencies are excluded: they never reach a user's install tree.
 *
 * The walk reads manifests OFF DISK rather than via `require.resolve`. That is
 * load-bearing, not a style choice: `require.resolve("<pkg>/package.json")` is
 * gated by the package's `exports` map, and a package that does not export
 * `./package.json` throws `ERR_PACKAGE_PATH_NOT_EXPORTED`. The first version of
 * this test resolved that way, so it silently skipped commander, chalk, ora,
 * @sigstore/protobuf-specs and — via a `{"type":"commonjs"}` stub manifest —
 * the whole @modelcontextprotocol/sdk subtree: 30 of 120 packages checked,
 * including one of the four deps this test's own comment names. A guard that
 * cannot see the dep it was written for certifies nothing.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import semver from "semver";
import { parse as parseYaml } from "yaml";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

interface PackageManifest {
  readonly name?: string;
  readonly version?: string;
  readonly engines?: { readonly node?: string };
  readonly dependencies?: Readonly<Record<string, string>>;
  readonly optionalDependencies?: Readonly<Record<string, string>>;
}

function readManifest(dir: string): PackageManifest {
  return JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PackageManifest;
}

function runtimeDepNames(manifest: PackageManifest): readonly string[] {
  return [
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.optionalDependencies ?? {}),
  ];
}

/**
 * Node's `node_modules` lookup, done with `fs` instead of the resolver: walk up
 * from `from` looking for `<dir>/node_modules/<name>/package.json`. Returns the
 * REAL path so pnpm's symlinks into `.pnpm/` dedupe, and so the next level of
 * the walk starts inside the store where that package's own deps live.
 */
function findPackageDir(name: string, from: string): string | null {
  let current = resolve(from);
  for (;;) {
    const candidate = join(current, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) return realpathSync(candidate);
    const parent = dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

/**
 * The Node majors ci.yml's matrix builds on, read from the workflow itself rather
 * than mirrored here. The matrix is now load-bearing for two separate guards — this
 * one, and ci.yml's own per-leg `@types/node` typecheck — so a hand-synced copy is
 * exactly the drift this file exists to prevent.
 */
function ciMatrixMajors(): readonly number[] {
  const wf = parseYaml(readFileSync(join(rootDir, ".github", "workflows", "ci.yml"), "utf8")) as {
    jobs?: Record<string, { strategy?: { matrix?: Record<string, unknown> } }>;
  };
  const raw = wf.jobs?.["build-and-test"]?.strategy?.matrix?.["node-version"];
  if (!Array.isArray(raw)) return [];
  return raw.map((v) => Number(String(v).split(".")[0]));
}

interface ClosureEntry {
  readonly id: string;
  readonly range: string;
}

interface Closure {
  /** Package names reached, for the direct-dependency coverage assertion. */
  readonly names: ReadonlySet<string>;
  /** Packages that declare `engines.node`. */
  readonly declaring: readonly ClosureEntry[];
}

/** The transitive runtime closure, as npm would install it. */
function runtimeClosure(): Closure {
  const visitedDirs = new Set<string>();
  const names = new Set<string>();
  const declaring: ClosureEntry[] = [];

  const walk = (name: string, from: string): void => {
    const dir = findPackageDir(name, from);
    if (dir === null || visitedDirs.has(dir)) return;
    visitedDirs.add(dir);
    names.add(name);

    const manifest = readManifest(dir);
    const range = manifest.engines?.node;
    if (range !== undefined) {
      declaring.push({ id: `${manifest.name ?? name}@${manifest.version ?? "?"}`, range });
    }
    for (const dep of runtimeDepNames(manifest)) walk(dep, dir);
  };

  for (const dep of runtimeDepNames(readManifest(rootDir))) walk(dep, rootDir);
  return { names, declaring };
}

describe("engines.node ↔ dependency engines", () => {
  const declared = readManifest(rootDir).engines?.node;

  it("declares a valid node range", () => {
    expect(declared).toBeTypeOf("string");
    expect(semver.validRange(declared as string)).not.toBeNull();
  });

  it("reaches every direct runtime dependency", () => {
    // Guard the guard. The previous resolver silently dropped whole subtrees,
    // and a bare "did we find some packages" floor stayed satisfied by the 16
    // @inquirer entries while 90 packages went unchecked. Naming the direct
    // deps makes that specific failure impossible: it is the set this repo
    // controls, so a miss here is always a bug in the walk, never a dep's doing.
    const { names } = runtimeClosure();
    const direct = runtimeDepNames(readManifest(rootDir));
    expect(direct.filter((n) => !names.has(n))).toEqual([]);
  });

  it("is a SUBSET of every runtime dependency's engines.node", () => {
    const { declaring } = runtimeClosure();

    // A floor calibrated to the MEASURED closure (120 declaring packages when
    // written), not to a number small enough for any accident to clear it.
    expect(declaring.length).toBeGreaterThan(80);

    const violations = declaring
      .filter(({ range }) => !semver.subset(declared as string, range, { includePrerelease: true }))
      .map(({ id, range }) => `${id} requires "${range}"`);

    expect(
      violations,
      `package.json declares engines.node "${declared}", which promises support for Node ` +
        `versions these dependencies do not support. Users on those versions get EBADENGINE ` +
        `on install (a hard failure under engine-strict). Narrow engines.node to the ` +
        `intersection, or move off the dependency.`,
    ).toEqual([]);
  });

  it("admits every node major the CI matrix builds against", () => {
    // setup-node resolves each matrix entry to the latest minor of that major. If a
    // narrowing excluded a whole major, CI would keep passing while shipping a
    // package it cannot install there.
    //
    // `satisfies` against a very high minor is the whole check. An earlier version
    // also accepted a substring match on the rendered range, which could report a
    // major as admitted because its digits appeared in someone else's MINOR —
    // "^24.22.0" renders containing "22." and would have "admitted" 22.
    const majors = ciMatrixMajors();

    // Guard the guard. A renamed job, a restructured matrix, or an unreadable
    // workflow must FAIL here — an empty list would make the loop below vacuous
    // and this test would certify nothing while staying green.
    expect(majors.length, "could not read node-version matrix from ci.yml").toBeGreaterThan(0);
    expect(majors.every((m) => Number.isInteger(m) && m > 0)).toBe(true);

    for (const major of majors) {
      expect(
        semver.satisfies(`${major}.999.999`, declared as string),
        `engines.node "${declared}" excludes every Node ${major}.x, but ci.yml builds on ${major}`,
      ).toBe(true);
    }
  });
});

/**
 * The declared range is also written out in PROSE, in three files no semantic
 * check can reach: `README.md` is the user-facing promise, `CONTRIBUTING.md`
 * tells a contributor what to install, and `CLAUDE.md` is read into every
 * Claude Code session on this repo — so a stale copy there misinforms the agent
 * doing the work.
 *
 * The subset assertion above structurally cannot catch this. A within-major
 * narrowing (say `^22.24.0`) is still a subset of every dependency's range, so
 * the whole suite stays green while all three copies go stale. Not
 * hypothetical: CONTRIBUTING.md said "Node.js >= 22" against a declared
 * `>=22.9.0` for about three and a half weeks.
 *
 * `CHANGELOG.md` is deliberately NOT in the list, and neither is this file's
 * own header. Both state what was true at a past release; freezing them to the
 * current value is what would make them wrong.
 *
 * Matched against a whitespace-collapsed copy of each file, so that reflowing a
 * paragraph across the range is not a failure — markdown renders that newline
 * as a space, and the doc is still correct.
 *
 * Verbatim containment ONLY. README also restates the range in human form
 * ("22.22.2+, 24.15.0+ or 26+"), which this cannot check: deriving it would
 * have to know that ">=26.0.0" was written "26+". That is the ceiling. It is
 * survivable because a failure here points at the same sentence, so whoever
 * fixes the quoted range is looking straight at the prose restating it.
 */
describe("engines.node ↔ the docs that quote it", () => {
  const declared = readManifest(rootDir).engines?.node as string;

  for (const file of ["README.md", "CONTRIBUTING.md", "CLAUDE.md"]) {
    it(`${file} quotes the declared range verbatim`, () => {
      const text = readFileSync(join(rootDir, file), "utf8").replace(/\s+/g, " ");
      expect(
        text.includes(declared),
        `${file} does not contain engines.node "${declared}". package.json is the source ` +
          `of truth — update the range where that file writes it out.`,
      ).toBe(true);
    });
  }
});
