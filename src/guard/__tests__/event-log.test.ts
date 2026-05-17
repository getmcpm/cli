/**
 * Tests for event-log.ts — best-effort JSONL writer (v0.5.0 Step 10).
 */

import { describe, expect, test, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { appendEvent, buildEventLogEntry } from "../event-log.js";
import { _resetCachedStorePath } from "../../store/index.js";

let tmpHome: string;
let originalHome: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(path.join(tmpdir(), "mcpm-guard-events-test-"));
  originalHome = process.env.HOME;
  process.env.HOME = tmpHome;
  _resetCachedStorePath();
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  _resetCachedStorePath();
  rmSync(tmpHome, { recursive: true, force: true });
});

describe("buildEventLogEntry", () => {
  test("includes ts, server_name, direction, action, sanitized findings", () => {
    const entry = buildEventLogEntry(
      {
        ts: "2026-05-17T00:00:00Z",
        direction: "child->parent",
        action: "block",
        findings: [
          {
            signature_id: "owasp-mcp-2-instruction-injection-in-response",
            category: "OWASP-MCP-2",
            severity: "critical",
            target: "tool_response",
            matched_text_excerpt: "Ignore previous instructions",
            remediation: "do thing",
          },
        ],
      },
      "evil\x1b[2mserver", // ANSI escape in name
    );
    expect(entry.server_name).toBe("evilserver"); // sanitized
    expect(entry.action).toBe("block");
    expect(entry.findings[0]?.signature_id).toBe("owasp-mcp-2-instruction-injection-in-response");
  });
});

describe("appendEvent (filesystem round-trip)", () => {
  test("creates ~/.mcpm/guard-events.jsonl and appends one JSON line per call", async () => {
    await appendEvent(
      {
        ts: "2026-05-17T00:00:00Z",
        direction: "child->parent",
        action: "block",
        findings: [
          {
            signature_id: "sig-1",
            category: "OWASP-MCP-2",
            severity: "critical",
            target: "tool_response",
            matched_text_excerpt: "match",
            remediation: "r",
          },
        ],
      },
      "fs-mcp",
    );
    await appendEvent(
      {
        ts: "2026-05-17T00:00:01Z",
        direction: "child->parent",
        action: "warn",
        findings: [
          {
            signature_id: "sig-2",
            category: "OWASP-MCP-7",
            severity: "high",
            target: "tool_call_args",
            matched_text_excerpt: "match2",
            remediation: "r2",
          },
        ],
      },
      "fs-mcp",
    );

    const filePath = path.join(tmpHome, ".mcpm", "guard-events.jsonl");
    expect(existsSync(filePath)).toBe(true);
    const lines = readFileSync(filePath, "utf-8").trim().split("\n");
    expect(lines).toHaveLength(2);
    const parsed1 = JSON.parse(lines[0] ?? "{}");
    const parsed2 = JSON.parse(lines[1] ?? "{}");
    expect(parsed1.action).toBe("block");
    expect(parsed2.action).toBe("warn");
    expect(parsed1.server_name).toBe("fs-mcp");
  });

  test("write failure is non-blocking (no throw)", async () => {
    // CAUTION: do NOT just `delete process.env.HOME` — os.homedir() falls
    // back to the real user home (/Users/<user>) and the write would
    // actually succeed AGAINST THE REAL HOME directory, leaking test
    // artifacts. Caught during E2E smoke test.
    //
    // Instead: point HOME at an existing FILE (not a directory). mkdir
    // then fails with ENOTDIR, which the appendEvent catch swallows.
    const { writeFileSync } = await import("node:fs");
    const blocker = path.join(tmpHome, "homefile");
    writeFileSync(blocker, "not-a-directory");
    process.env.HOME = blocker;
    _resetCachedStorePath();
    await expect(
      appendEvent(
        {
          ts: "2026-05-17T00:00:00Z",
          direction: "child->parent",
          action: "block",
          findings: [],
        },
        "x",
      ),
    ).resolves.toBeUndefined();
  });
});
