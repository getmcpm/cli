/**
 * F1 PR4: confine CLI wiring — computeConfineMarkers, `enable --confine`
 * end-to-end, and `doctor-confine`. Isolated HOME (real adapters + real store)
 * with MCPM_DISABLE_CONFINE=1 so the OS-backend result is deterministic across
 * platforms (marker embedding + the store don't depend on the backend).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { _resetCachedStorePath } from "../../store/index.js";
import { getConfigPath } from "../../config/paths.js";
import {
  computeConfineMarkers,
  runEnableCommand,
  runDoctorConfineCommand,
} from "../cli.js";
import { readConfineStore } from "../confine/store.js";

let tmpHome: string;
let originalHome: string | undefined;

const cursorConfig = () => getConfigPath("cursor"); // ~/.cursor/mcp.json

function writeCursor(servers: Record<string, unknown>): void {
  const p = cursorConfig();
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, JSON.stringify({ mcpServers: servers }, null, 2), { mode: 0o600 });
}

function readCursor(): Record<string, { command?: string; args?: string[] }> {
  return JSON.parse(readFileSync(cursorConfig(), "utf-8")).mcpServers;
}

const collect = () => {
  const out: string[] = [];
  return { write: (s: string) => void out.push(s), text: () => out.join("") };
};

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-confine-cli-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  process.env.MCPM_DISABLE_CONFINE = "1"; // deterministic: backend "unavailable"
  _resetCachedStorePath();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  delete process.env.MCPM_DISABLE_CONFINE;
  _resetCachedStorePath();
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("computeConfineMarkers", () => {
  test("derives+stores a marker for an unwrapped stdio server; skips url + already-wrapped", async () => {
    writeCursor({
      "fs-mcp": { command: "npx", args: ["-y", "fs"] },
      "http-mcp": { url: "https://example.com/mcp" }, // no command → skip
      // an already-wrapped entry → skip (its args carry the guard marker)
      "wrapped-mcp": { command: "mcpm", args: ["guard", "run", "--inner", "--server-name", "wrapped-mcp", "--orig-hash", "x", "--", "node", "s.js"] },
    });
    const io = collect();

    const markers = await computeConfineMarkers({ write: io.write });

    expect([...markers.keys()]).toEqual(["fs-mcp"]);
    const m = markers.get("fs-mcp")!;
    expect(m.profileHash).toMatch(/^[0-9a-f]{64}$/);
    // Persisted to the store.
    const store = await readConfineStore();
    expect(Object.keys(store.servers)).toEqual(["fs-mcp"]);
    expect(store.servers["fs-mcp"]?.tier).toBe("standard");
  });

  test("--server filter narrows to one server; merges into an existing store", async () => {
    writeCursor({
      alpha: { command: "node", args: ["a.js"] },
      beta: { command: "node", args: ["b.js"] },
    });
    await computeConfineMarkers({ server: "alpha", write: collect().write });
    // Second run enrolls beta; alpha must survive (merge, not clobber).
    const markers = await computeConfineMarkers({ server: "beta", write: collect().write });
    expect([...markers.keys()]).toEqual(["beta"]);
    const store = await readConfineStore();
    expect(Object.keys(store.servers).sort()).toEqual(["alpha", "beta"]);
  });

  test("no wrappable stdio servers → empty map, no store write", async () => {
    writeCursor({ "http-mcp": { url: "https://example.com/mcp" } });
    const markers = await computeConfineMarkers({ write: collect().write });
    expect(markers.size).toBe(0);
  });
});

describe("runEnableCommand --confine (end-to-end)", () => {
  test("wraps the server WITH the confine marker + writes the profile to the store", async () => {
    writeCursor({ probe: { command: "node", args: ["x.js"] } });
    const io = collect();

    await runEnableCommand({ confine: "standard", write: io.write });

    const entry = readCursor().probe;
    expect(entry.args).toContain("--confine-profile-hash");
    expect(entry.args).toContain("--"); // marker precedes the original argv
    expect(entry.args?.slice(-2)).toEqual(["node", "x.js"]);
    const store = await readConfineStore();
    expect(store.servers.probe?.tier).toBe("standard");
    // Backend forced unavailable → the enroll notice warns it runs unconfined.
    expect(io.text()).toContain("enrolled in OS confinement");
    expect(io.text()).toContain("UNCONFINED");
  });

  test("without --confine, no marker + no store (unchanged behavior)", async () => {
    writeCursor({ probe: { command: "node", args: ["x.js"] } });
    await runEnableCommand({ write: collect().write });
    expect(readCursor().probe.args).not.toContain("--confine-profile-hash");
    // No confine store created.
    const store = await readConfineStore();
    expect(Object.keys(store.servers)).toEqual([]);
  });
});

describe("runDoctorConfineCommand", () => {
  test("--json reports platform, backendAvailable, and enrolled servers", async () => {
    writeCursor({ probe: { command: "node", args: ["x.js"] } });
    await computeConfineMarkers({ write: collect().write });
    const io = collect();

    await runDoctorConfineCommand({ json: true, write: io.write });

    const report = JSON.parse(io.text());
    expect(report.platform).toBe(process.platform);
    expect(report.backendAvailable).toBe(false); // MCPM_DISABLE_CONFINE=1
    expect(report.servers.map((s: { name: string }) => s.name)).toContain("probe");
  });

  test("text mode lists enrolled servers + the unconfined-here notice", async () => {
    writeCursor({ probe: { command: "node", args: ["x.js"] } });
    await computeConfineMarkers({ write: collect().write });
    const io = collect();
    await runDoctorConfineCommand({ write: io.write });
    expect(io.text()).toContain("probe");
    expect(io.text()).toContain("UNAVAILABLE");
  });

  test("no enrollment → clear empty-state message", async () => {
    const io = collect();
    await runDoctorConfineCommand({ write: io.write });
    expect(io.text()).toContain("No servers enrolled");
  });
});
