/**
 * `mcpm verify` — repo-only, client-free lockfile integrity gate (D2).
 *
 * Unlike `mcpm up --frozen`, this runs on a hosted CI runner with ZERO AI clients
 * installed: it loads `mcpm-lock.yaml` and runs the shared frozen verify pass
 * (`classifyIntegrity` + `frozenVerdict`) with the SAME block semantics — integrity
 * drift / unverifiable record / format mismatch / suspicious missing baseline → BLOCK
 * (exit 1). It does NOT detect clients, read `~/.mcpm`, or write anything.
 *
 * ONE verb: B3 later extends `mcpm verify` with Sigstore provenance. Integrity now,
 * provenance later — never two meanings.
 *
 * HONESTY BOUNDARY (inherited from F3): a block means npm's PUBLISHED RECORD diverged
 * from your lock — NOT that mcpm caught malicious bytes. npx/uvx fetch the artifact
 * independently at server launch.
 */

import type { LockFile } from "../stack/schema.js";
import {
  classifyIntegrity,
  frozenVerdict,
  type FetchNpmIntegrity,
  type FrozenBlock,
} from "../stack/frozen-verify.js";

export interface VerifyDeps {
  /** Returns the parsed lock, or null when the file does not exist. */
  parseLock: (path: string) => Promise<LockFile | null>;
  fetchNpmIntegrity: FetchNpmIntegrity;
  output: (text: string) => void;
}

export interface VerifyBlocked {
  name: string;
  reason: FrozenBlock["reason"];
  identifier?: string;
  npmVersion?: string;
}

export interface VerifyModel {
  schemaVersion: 1;
  ok: boolean;
  /** npm servers whose published record matched the lock. */
  verified: number;
  /** npm servers that had a baseline to check. */
  checkedNpmCount: number;
  /** the benign refuse-to-run: the whole lock predates baselines / was locked offline. */
  noBaselines: boolean;
  blocked: VerifyBlocked[];
  /** pypi/oci/url servers with no baseline mechanism — reported, never blocked. */
  unenforceable: string[];
  /** set only when the lock could not be loaded at all. */
  error?: string;
}

export interface VerifyOpts {
  json?: boolean;
  /** Path to mcpm.yaml; the lock is derived as `<name>-lock.yaml`. Default `mcpm.yaml`. */
  stackFile?: string;
}

/**
 * @returns exit code: 0 = verified, 1 = block / could-not-load.
 */
export async function verifyHandler(deps: VerifyDeps, opts: VerifyOpts = {}): Promise<number> {
  const stackPath = opts.stackFile ?? "mcpm.yaml";
  const lockPath = stackPath.replace(/\.yaml$/, "-lock.yaml");

  const lockFile = await deps.parseLock(lockPath);
  if (lockFile === null) {
    // Deterministic gate: verify NEVER auto-locks (that would defeat the point in CI).
    const error = `no lock file found at ${lockPath} — run \`mcpm lock\` first.`;
    const model: VerifyModel = {
      schemaVersion: 1,
      ok: false,
      verified: 0,
      checkedNpmCount: 0,
      noBaselines: false,
      blocked: [],
      unenforceable: [],
      error,
    };
    if (opts.json) deps.output(JSON.stringify(model, null, 2));
    else deps.output(`\n✗ ${error}`);
    return 1;
  }

  const v = frozenVerdict(await classifyIntegrity(lockFile, deps.fetchNpmIntegrity));

  const blocked: VerifyBlocked[] = v.blocks.map((b) =>
    b.reason === "missing-baseline"
      ? { name: b.name, reason: b.reason }
      : { name: b.name, reason: b.reason, identifier: b.identifier, npmVersion: b.npmVersion }
  );
  // "checkable" npm servers minus those that failed a checkable reason. missing-baseline
  // blocks are NOT in checkedNpmCount, so they don't subtract here.
  const failedCheckable = v.blocks.filter((b) => b.reason !== "missing-baseline").length;

  const model: VerifyModel = {
    schemaVersion: 1,
    ok: v.ok,
    verified: v.checkedNpmCount - failedCheckable,
    checkedNpmCount: v.checkedNpmCount,
    noBaselines: v.noBaselines,
    blocked,
    unenforceable: v.unenforceable,
  };

  if (opts.json) {
    deps.output(JSON.stringify(model, null, 2));
  } else {
    renderVerifyText(model, deps.output);
  }
  return model.ok ? 0 : 1;
}

const REASON_PHRASE: Record<FrozenBlock["reason"], string> = {
  drift: "npm's published record changed since you locked it (integrity drift) — re-pin with `mcpm lock` only if expected",
  format:
    "cannot compare npm's published record against your locked baseline (integrity format changed) — re-run `mcpm lock`",
  "could-not-verify":
    "could not verify npm's published record this run (offline, a yanked version, or no comparable dist.integrity) — re-run; if it persists, investigate before dropping the check",
  "missing-baseline":
    "no integrity baseline recorded, though other servers in this lock have one — re-run `mcpm lock` online",
};

function renderVerifyText(model: VerifyModel, output: (text: string) => void): void {
  output("");
  output("mcpm verify");
  output("");

  if (model.noBaselines) {
    output(
      "  ✗ this lock has no integrity baselines (it predates them, or was last locked offline)."
    );
    output("    Run `mcpm lock` online once to record them, then `mcpm verify`.");
    return;
  }

  if (model.unenforceable.length > 0) {
    output(
      `  ⚠ ${model.unenforceable.length} server(s) (pypi/oci/url) have no integrity baseline mechanism — verify cannot enforce them (multi-registry pinning is deferred).`
    );
  }

  if (model.ok) {
    const word = model.verified === 1 ? "server" : "servers";
    output(`  ✓ ${model.verified} npm ${word} verified against npm's published record.`);
    return;
  }

  for (const b of model.blocked) {
    const who = b.identifier ? `${b.identifier}@${b.npmVersion}` : b.name;
    output(`  ✗ ${who}: ${REASON_PHRASE[b.reason]}`);
  }
  output("");
  output(
    `verification failed: ${model.blocked.length} server(s). mcpm checks the registry's published record, not the code your agent runs.`
  );
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import chalk from "chalk";
import { parseLockFile } from "../stack/schema.js";
import { fetchNpmIntegrity as _fetchNpmIntegrity } from "../registry/npm-integrity.js";

function coloredOutput(text: string): void {
  if (text.startsWith("  ✓")) console.log(chalk.green(text));
  else if (text.startsWith("  ✗")) console.log(chalk.red(text));
  else if (text.startsWith("  ⚠")) console.log(chalk.yellow(text));
  else console.log(text);
}

export function registerVerifyCommand(program: Command): void {
  program
    .command("verify")
    .description("Verify mcpm-lock.yaml integrity against npm's published record (repo-only CI gate)")
    .option("--json", "emit the structured verify model as JSON (shape UNSTABLE)")
    .option("-f, --file <path>", "path to mcpm.yaml (the lock is derived as <name>-lock.yaml)")
    .action(async (opts: { json?: boolean; file?: string }) => {
      const code = await verifyHandler(
        {
          parseLock: parseLockFile,
          fetchNpmIntegrity: (id, v) => _fetchNpmIntegrity(id, v),
          output: opts.json ? (t) => console.log(t) : coloredOutput,
        },
        { json: opts.json, stackFile: opts.file }
      );
      process.exit(code);
    });
}
