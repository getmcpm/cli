/**
 * A consumer that closes the pipe early must not look like an mcpm crash.
 *
 * `mcpm guard list-signatures | head -1` printed its first line and then died
 * with `node:events:505 throw er; // Unhandled 'error' event`, a 29-line stack
 * and exit 1 — reproduced against the published 0.41.0. Any mcpm output piped to
 * a reader that quits early (`head`, `grep -q`, a pager) hit this.
 *
 * Driven through the BUILT binary against a real closed pipe rather than through
 * a mocked stream: the defect is in how Node's stdout socket behaves when the
 * other end goes away, which a fake `write` cannot reproduce. The shell runs the
 * real pipeline so the failure mode is the user's, not an approximation.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync, execSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const BIN = path.resolve(process.cwd(), "dist/index.js");

beforeAll(() => {
  if (!existsSync(BIN)) {
    execSync("npm run build", { cwd: process.cwd(), timeout: 180_000, stdio: "ignore" });
  }
}, 200_000);

/**
 * Run `mcpm <args> | head -<n>` through a shell and report mcpm's OWN exit code
 * plus its stderr — a plain pipeline reports `head`'s status, which is 0 either
 * way and would make this test pass against the bug.
 */
function pipeToHead(args: string[], lines: number): { mcpmCode: number; stderr: string } {
  const cmd = [
    `"${process.execPath}" "${BIN}" ${args.map((a) => `"${a}"`).join(" ")} 2>/tmp/mcpm-epipe-err.$$`,
    `head -${lines} >/dev/null`,
  ].join(" | ");
  const r = spawnSync(
    "/bin/sh",
    ["-c", `${cmd}; echo "\${PIPESTATUS[0]:-$?}"; cat /tmp/mcpm-epipe-err.$$; rm -f /tmp/mcpm-epipe-err.$$`],
    { encoding: "utf-8", timeout: 60_000 }
  );
  const out = (r.stdout ?? "").split("\n");
  return { mcpmCode: Number(out[0]), stderr: out.slice(1).join("\n") };
}

describe("CLI — EPIPE on an early-closing consumer", () => {
  it.each([
    ["guard list-signatures", ["guard", "list-signatures"]],
    ["--help", ["--help"]],
  ])("%s | head -1 exits cleanly with no stack trace", (_label, args) => {
    const { mcpmCode, stderr } = pipeToHead(args, 1);
    expect(stderr).not.toMatch(/Unhandled 'error' event/);
    expect(stderr).not.toMatch(/EPIPE/);
    expect(stderr).not.toMatch(/at process\./);
    expect(mcpmCode).toBe(0);
  });
});
