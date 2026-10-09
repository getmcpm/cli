import { expect, test } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const fixtureRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "mcptox");
const cli = path.resolve("dist/index.js");
const fixtures = ["benign", "warn", "attacks"].flatMap((dir) =>
  readdirSync(path.join(fixtureRoot, dir)).filter((name) => name.startsWith("modern-")).map((name) =>
    JSON.parse(readFileSync(path.join(fixtureRoot, dir, name), "utf8")) as {
      name: string; expected_action: string; message: { result: unknown };
    },
  ),
);

test("compiled guard inspect and real guarded stdio agree on modern fixtures", async () => {
  const scratch = await mkdtemp(path.join(tmpdir(), "mcpm-modern-relay-"));
  const results = fixtures.map((fixture) => fixture.message.result);
  results.push({ protocolVersion: "2025-11-25", capabilities: { tools: {} }, serverInfo: { name: "weather", version: "1" } });
  const server = `
    const results = ${JSON.stringify(results)};
    require('node:readline').createInterface({input: process.stdin}).on('line', line => {
      const request = JSON.parse(line);
      process.stdout.write(JSON.stringify({jsonrpc:'2.0', id:request.id, result:results[request.params.index]})+'\\n');
    });
  `;
  const guard = spawn(process.execPath, [cli, "guard", "run", "--inner", "--server-name", "modern", "--", process.execPath, "-e", server], {
    env: { PATH: process.env.PATH, HOME: scratch, TMPDIR: scratch }, stdio: ["pipe", "pipe", "pipe"],
  });
  let stderr = "";
  guard.stderr.on("data", (chunk) => { stderr += chunk; });
  const exit = new Promise<number | null>((resolve, reject) => { guard.on("exit", resolve); guard.on("error", reject); });
  const reader = createInterface({ input: guard.stdout });
  const lines = reader[Symbol.asyncIterator]();
  try {
    for (const [index, fixture] of fixtures.entries()) {
      const inspected = spawnSync(process.execPath, [cli, "guard", "inspect", "--json"], {
        input: JSON.stringify({ jsonrpc: "2.0", id: index, result: fixture.message.result }), encoding: "utf8", timeout: 10_000,
        env: { PATH: process.env.PATH, HOME: scratch, TMPDIR: scratch },
      });
      expect(inspected.status, fixture.name).toBe({ pass: 0, warn: 1, block: 2 }[fixture.expected_action]);
      expect(JSON.parse(inspected.stdout).action, fixture.name).toBe(fixture.expected_action);
      guard.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: index, method: "tools/call", params: {
        name: "fixture", index, _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} },
      } }) + "\n");
      const response = JSON.parse((await lines.next()).value!);
      expect(response.id, fixture.name).toBe(index);
      if (fixture.expected_action === "block") {
        expect(response.error.message, fixture.name).toBe("BLOCKED by mcpm-guard");
        expect(response.result).toBeUndefined();
      } else {
        expect(response.result, fixture.name).toEqual(fixture.message.result);
      }
    }
    // A legacy initialize still traverses the same process and captures its own pin.
    guard.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: "legacy", method: "initialize", params: { index: fixtures.length } }) + "\n");
    expect(JSON.parse((await lines.next()).value!).result.protocolVersion).toBe("2025-11-25");
    guard.stdin.end();
    expect(await exit, stderr).toBe(0);
    const pins = JSON.parse(await readFile(path.join(scratch, ".mcpm", "pins.json"), "utf8"));
    expect(pins.handshakes.modern).toBeDefined();
    const events = (await readFile(path.join(scratch, ".mcpm", "guard-events.jsonl"), "utf8")).trim().split("\n").map((line) => JSON.parse(line));
    expect(events.map((event) => event.action)).toEqual(fixtures.filter((f) => f.expected_action !== "pass").map((f) => f.expected_action));
    expect(events.some((event) => event.findings.some((f: { signature_id: string }) => f.signature_id === "guard-unsupported-input-request"))).toBe(true);
  } finally {
    guard.kill();
    reader.close();
    await exit;
    await rm(scratch, { recursive: true, force: true });
  }
}, 30_000);
