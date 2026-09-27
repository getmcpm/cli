/**
 * Real multi-process regression test for #232 (backlog #111): pins.json
 * read-modify-write races under concurrent guard sessions.
 *
 * Every other pins/drift test uses an in-memory fake for `updatePins`'s
 * dependencies or drives a single in-process `readPins`/`writePins` pair —
 * neither exercises `proper-lockfile`'s actual CROSS-PROCESS locking, which is
 * exactly where the bug lived (two separate `mcpm guard run --inner`
 * processes, each composing an unlocked read with a later write). This test
 * spawns N REAL, separate `node` processes (the built `dist/index.js`, via
 * `mcpm guard run --inner`) against ONE throwaway HOME, each driven by a
 * conformant MCP client (initialize -> wait -> notifications/initialized +
 * tools/list -> wait -> close stdin) — the same shape an IDE launching a whole
 * server stack produces, and the same harness used for the CHANGELOG's
 * measured loss numbers (see scripts referenced there / storm.mjs in the PR
 * description).
 *
 * Requires a build (`pnpm build`) — SKIPPED otherwise, so a plain `pnpm test`
 * on a fresh checkout doesn't fail on a missing `dist/index.js`. CI runs
 * `pnpm build` before `pnpm test` (see package.json / CI workflow) so this
 * runs there; run `pnpm build` locally first to exercise it.
 *
 * Mutation check (done manually, not encoded here — see PR description): with
 * `run-inner.ts`'s tools-capture routed back through the pre-#232 shape
 * (`read: () => readPins().catch(() => pinsSnapshot), write: writePins`) this
 * test fails reliably (observed ~20-90% pin loss depending on N); with
 * `deps.update: updatePins` (this codebase) it passes.
 */

import { describe, test, expect } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = fileURLToPath(new URL("../../../dist/index.js", import.meta.url));
const HAS_DIST = existsSync(DIST);

// Minimal line-delimited JSON-RPC MCP stdio server: responds to initialize +
// tools/list (2 named tools), ignores notifications/initialized. Written to a
// temp file per test so no repo fixture is needed.
const FAKE_SERVER_SRC = `
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
let buf = "";
process.stdin.on("data", (d) => {
  buf += d.toString("utf8");
  let i;
  while ((i = buf.indexOf("\\n")) >= 0) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    handle(msg);
  }
});
process.stdin.on("end", () => process.exit(0));
function handle(msg) {
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "concurrency-fake-server", version: "1.0.0" },
    }});
  } else if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [
      { name: "alpha", description: "Alpha tool", inputSchema: { type: "object", properties: {} } },
      { name: "beta", description: "Beta tool", inputSchema: { type: "object", properties: {} } },
    ] } });
  }
}
`;

interface ClientResult {
  readonly code: number | null;
  readonly stderr: string;
}

function runOneSession(home: string, serverName: string, fakeServerPath: string): Promise<ClientResult> {
  return new Promise((resolve) => {
    const child = spawn(
      process.execPath,
      [DIST, "guard", "run", "--inner", "--server-name", serverName, "--", process.execPath, fakeServerPath],
      { env: { ...process.env, HOME: home }, stdio: ["pipe", "pipe", "pipe"] },
    );
    let stdoutBuf = "";
    let stderrBuf = "";
    let initReceived = false;
    let toolsReceived = false;
    let settled = false;

    const finish = (code: number | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, stderr: stderrBuf });
    };

    child.stdout.on("data", (d: Buffer) => {
      stdoutBuf += d.toString("utf8");
      let i: number;
      while ((i = stdoutBuf.indexOf("\n")) >= 0) {
        const line = stdoutBuf.slice(0, i);
        stdoutBuf = stdoutBuf.slice(i + 1);
        if (!line.trim()) continue;
        let msg: { id?: number };
        try {
          msg = JSON.parse(line) as { id?: number };
        } catch {
          continue;
        }
        if (msg.id === 1 && !initReceived) {
          initReceived = true;
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
          child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }) + "\n");
        } else if (msg.id === 2 && !toolsReceived) {
          toolsReceived = true;
          child.stdin.end();
        }
      }
    });
    child.stderr.on("data", (d: Buffer) => {
      stderrBuf += d.toString("utf8");
    });
    child.on("exit", (code) => finish(code));
    child.on("error", () => finish(-1));

    child.stdin.write(
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "pins-concurrency-test", version: "1.0.0" },
        },
      }) + "\n",
    );

    var timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(-1);
    }, 15_000);
  });
}

interface PinsFileShape {
  servers: Record<string, Record<string, { current_hash: string | null }>>;
  handshakes?: Record<string, { current_hash: string }>;
}

async function runRound(n: number): Promise<{ home: string; names: string[]; pins: PinsFileShape; results: ClientResult[] }> {
  const home = await mkdtemp(path.join(tmpdir(), "mcpm-pins-concurrency-"));
  const fakeServerPath = path.join(home, "fake-server.mjs");
  await writeFile(fakeServerPath, FAKE_SERVER_SRC);
  const names = Array.from({ length: n }, (_, i) => `srv${i}`);
  const results = await Promise.all(names.map((name) => runOneSession(home, name, fakeServerPath)));
  let pins: PinsFileShape = { servers: {} };
  try {
    pins = JSON.parse(await readFile(path.join(home, ".mcpm", "pins.json"), "utf-8")) as PinsFileShape;
  } catch {
    // absent/corrupt counts as total loss in the assertions below.
  }
  return { home, names, pins, results };
}

describe.skipIf(!HAS_DIST)("pins.json concurrency — real multi-process (#232)", () => {
  test(
    "N guard sessions racing to first-session-pin their OWN server at once lose no tool or handshake pin",
    async () => {
      // Two rounds, fresh HOME each — one round alone was enough to reproduce
      // the pre-#232 bug reliably (measured ~50% loss at N=2, ~87% at N=8), so
      // this stays comfortably CI-fast while not resting on a single sample.
      for (let round = 0; round < 2; round++) {
        const n = 8;
        const { home, names, pins, results } = await runRound(n);
        try {
          for (const r of results) {
            expect(r.code, `session exited non-zero: ${r.stderr}`).toBe(0);
          }
          for (const name of names) {
            const server = pins.servers[name] ?? {};
            expect(server.alpha?.current_hash, `${name}: missing alpha tool pin`).toMatch(/^sha256:[0-9a-f]{64}$/);
            expect(server.beta?.current_hash, `${name}: missing beta tool pin`).toMatch(/^sha256:[0-9a-f]{64}$/);
            expect(pins.handshakes?.[name]?.current_hash, `${name}: missing handshake pin`).toMatch(
              /^sha256:[0-9a-f]{64}$/,
            );
          }
        } finally {
          await rm(home, { recursive: true, force: true });
        }
      }
    },
    30_000,
  );
});
