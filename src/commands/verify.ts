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

import type { LockFile, StackFile } from "../stack/schema.js";
import { lockPathFor } from "../stack/paths.js";
import {
  classifyIntegrity,
  frozenVerdict,
  memoizeIntegrity,
  type FetchNpmIntegrity,
  type FrozenBlock,
} from "../stack/frozen-verify.js";
import {
  classifyProvenance,
  type FetchNpmProvenance,
  type ProvenanceBlock,
} from "../stack/frozen-provenance.js";

export interface VerifyDeps {
  /** Returns the parsed lock, or null when the file does not exist. */
  parseLock: (path: string) => Promise<LockFile | null>;
  /**
   * Returns the parsed stack, or null when mcpm.yaml does not exist (the lock is
   * then verified on its own terms). A malformed stack must THROW, not return
   * null — silently skipping the coverage gate is the failure it exists to catch.
   */
  parseStack: (path: string) => Promise<StackFile | null>;
  fetchNpmIntegrity: FetchNpmIntegrity;
  fetchNpmProvenance: FetchNpmProvenance;
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
  /**
   * npm servers whose crypto-`verified` provenance baseline regressed (F8 / B3).
   * Empty for every lock without a `verification.outcome==="verified"` server.
   */
  provenanceBlocked: ProvenanceBlock[];
  /** npm servers that carried a crypto-`verified` provenance baseline to re-check. */
  checkedProvenanceCount: number;
  /**
   * Servers mcpm.yaml declares that the lock does not contain — the lock enforces
   * LESS than was asked for. Always empty when there is no mcpm.yaml to compare against.
   */
  uncovered: string[];
  /**
   * The lock holds no servers at all AND there is no mcpm.yaml to confirm that is
   * intentional — so this run verified nothing and cannot claim otherwise.
   */
  vacuous: boolean;
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
  const lockPath = lockPathFor(stackPath);

  // Fail-closed: this handler NEVER throws — any error (a missing lock, a malformed /
  // Zod-invalid lock that makes parseLock throw, a fetch failure) resolves to exit 1
  // with a structured error model. That keeps the CI gate closed even when the
  // exported handler is reused programmatically (no ambient top-level catch).
  try {
    const lockFile = await deps.parseLock(lockPath);
    if (lockFile === null) {
      // Deterministic gate: verify NEVER auto-locks (that would defeat the point in CI).
      return emitError(deps, opts, `no lock file found at ${lockPath} — run \`mcpm lock\` first.`);
    }

    // Coverage: does the lock account for everything mcpm.yaml declares? A lock that
    // silently dropped servers (a failed `mcpm lock` in an older release, a hand-edit,
    // a bad merge) enforces less than the user asked for, and every OTHER gate reads
    // only the lock — so they all pass while coverage quietly shrinks. No mcpm.yaml
    // to compare against → nothing to check, not a failure (verify is lock-first).
    const stackFile = await deps.parseStack(stackPath);
    const uncovered =
      stackFile === null
        ? []
        : Object.keys(stackFile.servers).filter((name) => !(name in lockFile.servers));

    // A lock with zero servers verifies NOTHING, so it must never exit 0 on the
    // strength of gates that pass vacuously. Legitimate only when a stack file
    // positively confirms nothing was declared — with no mcpm.yaml we cannot tell
    // an empty project from a lock that lost its contents, and fail-closed picks
    // the second reading.
    const vacuous = Object.keys(lockFile.servers).length === 0 && stackFile === null;

    // Two independent, fail-closed gates run in parallel: integrity drift (H11) and
    // provenance crypto-regression (F8/B3). The run passes only if BOTH pass. Both
    // read npm's integrity per checked coordinate, so memoize the fetcher — one GET
    // per coordinate, and the two gates can never disagree about the same record.
    const fetchIntegrity = memoizeIntegrity(deps.fetchNpmIntegrity);
    const [v, pv] = await Promise.all([
      classifyIntegrity(lockFile, fetchIntegrity).then(frozenVerdict),
      classifyProvenance(lockFile, fetchIntegrity, deps.fetchNpmProvenance),
    ]);

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
      // THREE independent fail-closed gates. Coverage is the outermost: the other
      // two answer "is what's in the lock still good?", which passes VACUOUSLY over
      // an empty or truncated one. Without it, `servers: {}` verified green.
      ok: v.ok && pv.ok && uncovered.length === 0 && !vacuous,
      verified: v.checkedNpmCount - failedCheckable,
      checkedNpmCount: v.checkedNpmCount,
      noBaselines: v.noBaselines,
      blocked,
      unenforceable: v.unenforceable,
      provenanceBlocked: pv.blocks,
      checkedProvenanceCount: pv.checkedVerifiedCount,
      uncovered,
      vacuous,
    };

    if (opts.json) {
      deps.output(JSON.stringify(model, null, 2));
    } else {
      renderVerifyText(model, deps.output);
    }
    return model.ok ? 0 : 1;
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return emitError(deps, opts, `could not verify ${lockPath}: ${detail}`);
  }
}

/** Emit a fail-closed error (structured under --json) and return exit code 1. */
function emitError(deps: VerifyDeps, opts: VerifyOpts, error: string): number {
  const model: VerifyModel = {
    schemaVersion: 1,
    ok: false,
    verified: 0,
    checkedNpmCount: 0,
    noBaselines: false,
    blocked: [],
    unenforceable: [],
    provenanceBlocked: [],
    checkedProvenanceCount: 0,
    uncovered: [],
    vacuous: false,
    error,
  };
  if (opts.json) deps.output(JSON.stringify(model, null, 2));
  else deps.output(`\n✗ ${error}`);
  return 1;
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

const PROVENANCE_PHRASE: Record<ProvenanceBlock["reason"], string> = {
  "signer-changed":
    "cryptographic signer identity changed since you locked it — re-pin with `mcpm lock` only if this re-sign is expected",
  regression:
    "provenance regressed — the attestation verified when you locked it and no longer does",
  unverifiable:
    "could not cryptographically re-verify this run — re-run; if it persists, investigate before dropping the check",
};

function renderVerifyText(model: VerifyModel, output: (text: string) => void): void {
  output("");
  output("mcpm verify");
  output("");

  // Coverage dimension — printed FIRST because it reframes everything below it: on a
  // truncated lock the integrity line reads "✓ 0 npm servers verified", which is
  // literally true and thoroughly misleading on its own.
  if (model.uncovered.length > 0) {
    const word = model.uncovered.length === 1 ? "server" : "servers";
    output(
      `  ✗ ${model.uncovered.length} declared ${word} missing from the lock — it enforces less than mcpm.yaml declares:`
    );
    for (const name of model.uncovered) output(`      ${name}`);
    output("    Run `mcpm lock` to cover them. Until then the checks below cover only what IS locked.");
  }

  if (model.vacuous) {
    output("  ✗ this lock contains no servers — this run verified nothing.");
    output(
      "    No mcpm.yaml alongside it to confirm that is intentional, so this is not treated as a pass."
    );
  }

  // Integrity dimension (H11).
  if (model.noBaselines) {
    // Lock-wide integrity gap — benign (predates baselines / offline lock), normally a
    // refuse-to-run. But the sticky provenance carry-forward (lock.ts) can leave a
    // crypto-`verified` baseline on a lock whose integrity fetch failed, so a
    // provenance regression can coexist — print the benign note but DON'T stop before
    // the provenance blocks below (hiding a real signer swap behind it).
    output(
      "  ✗ this lock has no integrity baselines (it predates them, or was last locked offline)."
    );
    output("    Run `mcpm lock` online once to record them, then `mcpm verify`.");
    if (model.provenanceBlocked.length === 0) return;
  } else {
    if (model.unenforceable.length > 0) {
      output(
        `  ⚠ ${model.unenforceable.length} server(s) (pypi/oci/url) have no integrity baseline mechanism — verify cannot enforce them (multi-registry pinning is deferred).`
      );
    }
    if (model.blocked.length === 0) {
      // Only claim a ✓ when something was actually checked. "✓ 0 npm servers
      // verified" is literally true and reads as a pass — it is what made the
      // empty-lock fail-open look healthy.
      if (model.verified > 0) {
        const word = model.verified === 1 ? "server" : "servers";
        output(
          `  ✓ ${model.verified} npm ${word} verified against npm's published integrity record.`
        );
      } else if (
        !model.vacuous &&
        model.unenforceable.length === 0 &&
        model.uncovered.length === 0
      ) {
        // Passing with nothing checked and nothing to warn about (an empty declared
        // stack). Say so plainly rather than printing an empty report.
        output("  — nothing to verify: this stack declares no servers.");
      }
    } else {
      for (const b of model.blocked) {
        const who = b.identifier ? `${b.identifier}@${b.npmVersion}` : b.name;
        output(`  ✗ ${who}: ${REASON_PHRASE[b.reason]}`);
      }
    }
  }

  // Provenance dimension (F8/B3) — only surfaces when the lock had crypto-verified
  // baselines to re-check; otherwise silent (evidence-gated, zero output).
  if (model.provenanceBlocked.length > 0) {
    for (const b of model.provenanceBlocked) {
      output(`  ✗ ${b.identifier}@${b.npmVersion}: ${PROVENANCE_PHRASE[b.reason]} (${b.detail})`);
    }
  } else if (model.checkedProvenanceCount > 0) {
    // Verb on the ATTESTATION, not the server — "re-verified the server" would
    // over-claim the code was checked; only the build-identity attestation was.
    const word = model.checkedProvenanceCount === 1 ? "attestation" : "attestations";
    output(
      `  ✓ ${model.checkedProvenanceCount} npm server ${word} cryptographically re-verified (signer unchanged).`
    );
  }

  if (!model.ok) {
    // Count DISTINCT servers — a server that fails both integrity and provenance is
    // one failure, not two.
    const failed = new Set([
      ...model.blocked.map((b) => b.name),
      ...model.provenanceBlocked.map((b) => b.name),
      ...model.uncovered,
    ]);
    // A vacuous lock fails with no server to name — the ✗ above already said why,
    // and "verification failed: 0 server(s)" would read as a glitch.
    if (failed.size === 0) return;
    output("");
    output(
      `verification failed: ${failed.size} server(s). mcpm checks the registry's published record, not the code your agent runs.`
    );
  }
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { access } from "fs/promises";
import { parseLockFile, parseStackFile } from "../stack/schema.js";
import { fetchNpmIntegrity as _fetchNpmIntegrity } from "../registry/npm-integrity.js";
import { fetchNpmProvenance as _fetchNpmProvenance } from "../registry/npm-provenance.js";
import { coloredOutput } from "../utils/output.js";

export function registerVerifyCommand(program: Command): void {
  program
    .command("verify")
    .description(
      "Verify mcpm-lock.yaml against npm's published record — integrity drift + Sigstore provenance regression (repo-only CI gate)"
    )
    .option("--json", "emit the structured verify model as JSON (shape UNSTABLE)")
    .option("-f, --file <path>", "path to mcpm.yaml (the lock is derived as <name>-lock.yaml)")
    .action(async (opts: { json?: boolean; file?: string }) => {
      const code = await verifyHandler(
        {
          parseLock: parseLockFile,
          // Missing mcpm.yaml → null (coverage skipped). A PRESENT but malformed one
          // propagates out of parseStackFile to verify's fail-closed catch (exit 1) —
          // an unreadable stack must not silently disable the coverage gate.
          parseStack: async (p) => {
            try {
              await access(p);
            } catch {
              return null;
            }
            return parseStackFile(p);
          },
          fetchNpmIntegrity: (id, v) => _fetchNpmIntegrity(id, v),
          fetchNpmProvenance: (id, v, o) => _fetchNpmProvenance(id, v, o),
          output: opts.json ? (t) => console.log(t) : coloredOutput,
        },
        { json: opts.json, stackFile: opts.file }
      );
      process.exit(code);
    });
}
