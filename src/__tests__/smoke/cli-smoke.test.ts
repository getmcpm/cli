/**
 * CLI output-contract smoke matrix — the dogfood, shifted left.
 *
 * Spawns the BUILT binary (dist/index.js) in a throwaway HOME and asserts the
 * user-facing OUTPUT on edge paths: the "no-op / not-found" paths where commands
 * historically printed false success ("refreshed" / "Removed secret") while their
 * helper actually did nothing. Structural unit tests pass right past that class;
 * only an end-to-end output assertion catches it. Local-only commands (no registry)
 * so the matrix is deterministic and offline.
 *
 * CI builds (`pnpm run build`) before tests, so dist is fresh there. Locally we
 * build once if dist is missing — run `npm run build` first if iterating on a
 * command, since a stale dist would test old code.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync, execSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";

const BIN = path.resolve(process.cwd(), "dist/index.js");

beforeAll(() => {
  if (!existsSync(BIN)) {
    execSync("npm run build", { cwd: process.cwd(), timeout: 180_000, stdio: "ignore" });
  }
}, 200_000);

interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
  /** stdout + stderr combined, for convenience. */
  out: string;
}

function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(path.join(os.tmpdir(), "mcpm-smoke-"));
  try {
    fn(home);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

function run(args: string[], home: string): RunResult {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf-8",
    timeout: 30_000,
    input: "", // empty stdin → a command that waits for a TTY prompt fails fast instead of hanging
    env: { ...process.env, HOME: home, MCPM_DISABLE_OS_KEYCHAIN: "1" },
  });
  const stdout = r.stdout ?? "";
  const stderr = r.stderr ?? "";
  return { stdout, stderr, code: r.status ?? -1, out: `${stdout}\n${stderr}` };
}

describe("CLI smoke — sanity", () => {
  it("--version prints the package version and exits 0", () => {
    withHome((home) => {
      const r = run(["--version"], home);
      expect(r.code).toBe(0);
      expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });
});

describe("CLI smoke — no-op paths must not claim false success", () => {
  it("guard reset-integrity with no pins.json says 'nothing to refresh' (not 'refreshed')", () => {
    withHome((home) => {
      const r = run(["guard", "reset-integrity", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/nothing to refresh/i);
      expect(r.out).not.toMatch(/integrity refreshed/i);
    });
  });

  it("guard reset-integrity WITH a pins.json still says 'refreshed' (positive control)", () => {
    withHome((home) => {
      mkdirSync(path.join(home, ".mcpm"), { recursive: true });
      writeFileSync(path.join(home, ".mcpm", "pins.json"), '{"format_version":1,"servers":{}}');
      const r = run(["guard", "reset-integrity", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/integrity refreshed/i);
    });
  });

  it("guard accept-drift for an unknown server says 'nothing to re-pin' (not 're-pinned')", () => {
    withHome((home) => {
      const hash = `sha256:${"0".repeat(64)}`;
      const r = run(["guard", "accept-drift", "ghost-server", "--new-hash", hash, "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/no existing pin.*nothing to re-pin/i);
      expect(r.out).not.toMatch(/re-pinned to/i);
    });
  });

  it("guard accept-drift --remove for an unknown server says 'nothing to remove'", () => {
    withHome((home) => {
      const r = run(["guard", "accept-drift", "ghost-server", "--remove", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/no existing pin.*nothing to remove/i);
    });
  });

  it("secrets rm of a never-stored secret errors (not a false 'Removed secret') and exits non-zero", () => {
    withHome((home) => {
      const r = run(["secrets", "rm", "ghost", "NEVERSET", "-y"], home);
      expect(r.code).not.toBe(0);
      expect(r.out).toMatch(/no secret stored/i);
      expect(r.out).not.toMatch(/removed secret/i);
    });
  });
});

describe("CLI smoke — CI-gate exit codes (docs/CONTRACTS.md)", () => {
  it("sync --check exits 2 when clients disagree (the drift signal CI consumes)", () => {
    withHome((home) => {
      mkdirSync(path.join(home, ".cursor"), { recursive: true });
      mkdirSync(path.join(home, ".codeium", "windsurf"), { recursive: true });
      // cursor has `foo`; windsurf does not -> drift.
      writeFileSync(
        path.join(home, ".cursor", "mcp.json"),
        '{"mcpServers":{"foo":{"command":"echo","args":["a"]}}}',
      );
      writeFileSync(path.join(home, ".codeium", "windsurf", "mcp_config.json"), '{"mcpServers":{}}');
      const r = run(["sync", "--check"], home);
      expect(r.code).toBe(2);
      expect(r.out).toMatch(/foo/);
    });
  });

  it("sync --check exits 0 with no client configs (no false drift)", () => {
    withHome((home) => {
      const r = run(["sync", "--check"], home);
      expect(r.code).toBe(0);
    });
  });

  it("up --frozen exits 1 when the stack file is missing (fail-closed, not a false pass)", () => {
    withHome((home) => {
      const r = run(["up", "--frozen"], home);
      expect(r.code).toBe(1);
      expect(r.out).toMatch(/stack file not found/i);
    });
  });
});

describe("CLI smoke — generated completions are valid shell", () => {
  it("the bash completion script passes `bash -n` (syntax check)", () => {
    withHome((home) => {
      const script = run(["completions", "bash"], home).stdout;
      expect(script.length).toBeGreaterThan(0);
      const check = spawnSync("bash", ["-n"], { input: script, encoding: "utf-8", timeout: 10_000 });
      if (check.error && (check.error as NodeJS.ErrnoException).code === "ENOENT") return; // bash absent — skip
      expect(check.status, `bash -n rejected the script:\n${check.stderr}`).toBe(0);
    });
  });
});
