/**
 * Tests for run-inner.ts fail-safe loading + the SECURITY F3 same-session
 * drift guard.
 *
 *  - Fix 2: a pins-read error (PinsIntegrityError / I/O) must FAIL CLOSED —
 *    write a PINS-READ-ERROR to stderr and process.exit(1) rather than start
 *    the relay with rug-pull protection silently off.
 *  - Fix 3: a PolicyIntegrityError must be surfaced on stderr before falling
 *    back to the safe `{}` policy (full enforcement).
 *  - Fix 2 (MED): a generic non-ENOENT policy read error (EACCES/EMFILE) must
 *    be surfaced as POLICY-READ-ERROR before the same safe `{}` fallback.
 *  - Fix 7a: inspectForDriftSync's same-session guard (SECURITY F3).
 */

import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectForDriftSync } from "../run-inner.js";
import { hashToolDefinition, emptyPinsFile, type PinsFile } from "../pins.js";

// ──────────────────────── helpers ────────────────────────

const toolsListMsg = (
  toolName: string,
  description: string,
): JSONRPCMessage =>
  ({
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: toolName, description }] },
  }) as JSONRPCMessage;

// ─────────────── Fix 7a: same-session drift guard (SECURITY F3) ───────────────

describe("inspectForDriftSync — same-session guard (SECURITY F3)", () => {
  test("first tools/list passes and records its hash; second matching hash passes", () => {
    const pins = emptyPinsFile();
    const seen = new Map<string, string>();

    const first = inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, seen);
    expect(first.action).toBe("pass");
    // The hash was recorded for the (server, tool) pair.
    expect(seen.get("srv::read")).toBe(hashToolDefinition({ description: "v1" }));

    const secondSame = inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, seen);
    expect(secondSame.action).toBe("pass");
  });

  test("a second tools/list with a DIFFERENT hash in the same session blocks", () => {
    const pins = emptyPinsFile();
    const seen = new Map<string, string>();

    inspectForDriftSync(toolsListMsg("read", "v1"), "srv", pins, seen);
    const drifted = inspectForDriftSync(toolsListMsg("read", "v2-POISONED"), "srv", pins, seen);

    expect(drifted.action).toBe("block");
    expect(drifted.findings).toHaveLength(1);
    expect(drifted.findings[0]?.signature_id).toBe("schema-drift-in-session");
  });

  test("two different server names are independent (no cross-server bleed)", () => {
    const pins = emptyPinsFile();
    const seen = new Map<string, string>();

    inspectForDriftSync(toolsListMsg("read", "v1"), "alpha", pins, seen);
    // beta sends a different schema for the same tool name — must NOT block,
    // because the session key is namespaced by server name.
    const beta = inspectForDriftSync(toolsListMsg("read", "totally-different"), "beta", pins, seen);
    expect(beta.action).toBe("pass");
    expect(seen.get("alpha::read")).toBeDefined();
    expect(seen.get("beta::read")).toBeDefined();
  });
});

// ─────────────── Fix 2 + 3: fail-safe loading in runInner ───────────────

describe("runInner fail-safe loading", () => {
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    exitSpy = vi.spyOn(process, "exit").mockImplementation(((_code?: number) => {
      throw new Error("__EXIT__");
    }) as never);
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    exitSpy.mockRestore();
    stderrSpy.mockRestore();
    vi.resetModules();
    vi.doUnmock("../pins.js");
    vi.doUnmock("../policy.js");
  });

  const runInnerArgs = {
    serverName: "victim",
    command: "true",
    args: [] as string[],
    declaredEnvKeys: [] as string[],
  };

  test("Fix 2: a pins-read error fails closed (PINS-READ-ERROR + exit 1)", async () => {
    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return {
        ...actual,
        readPins: async () => {
          throw new actual.PinsIntegrityError("tampered sidecar");
        },
      };
    });

    const { runInner } = await import("../run-inner.js");
    await expect(runInner(runInnerArgs)).rejects.toThrow("__EXIT__");
    expect(exitSpy).toHaveBeenCalledWith(1);
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] PINS-READ-ERROR:");
    expect(stderr).toContain("guard-events.jsonl");
    expect(stderr).toContain("mcpm guard reset-integrity");
  });

  test("Fix 3: a PolicyIntegrityError is surfaced on stderr, then falls back to {}", async () => {
    vi.resetModules();
    // pins reads fine (empty), so the relay would otherwise proceed.
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return { ...actual, readPins: async (): Promise<PinsFile> => actual.emptyPinsFile() };
    });
    // Policy read throws a PolicyIntegrityError.
    vi.doMock("../policy.js", async () => {
      const actual = await vi.importActual<typeof import("../policy.js")>("../policy.js");
      return {
        ...actual,
        readPolicy: async () => {
          throw new actual.PolicyIntegrityError("guard-policy.yaml integrity check failed");
        },
      };
    });
    // Avoid spawning a real subprocess: stub the relay to resolve immediately.
    vi.doMock("../relay.js", async () => {
      const actual = await vi.importActual<typeof import("../relay.js")>("../relay.js");
      return {
        ...actual,
        startRelay: () => ({ child: {} as never, exit: Promise.resolve(0) }),
      };
    });

    const { runInner } = await import("../run-inner.js");
    const code = await runInner(runInnerArgs);
    expect(code).toBe(0); // fell back to full enforcement, relay started
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] POLICY-INTEGRITY-ERROR:");
    // Did NOT fail closed for a policy error (the {} fallback is the safe state).
    expect(exitSpy).not.toHaveBeenCalled();
  });

  test("Fix 2 (MED): a generic policy read error (EACCES) is surfaced as POLICY-READ-ERROR, then falls back to {}", async () => {
    vi.resetModules();
    vi.doMock("../pins.js", async () => {
      const actual = await vi.importActual<typeof import("../pins.js")>("../pins.js");
      return { ...actual, readPins: async (): Promise<PinsFile> => actual.emptyPinsFile() };
    });
    // Policy read throws a generic (non-PolicyIntegrityError, non-ENOENT) I/O error.
    vi.doMock("../policy.js", async () => {
      const actual = await vi.importActual<typeof import("../policy.js")>("../policy.js");
      return {
        ...actual,
        readPolicy: async () => {
          const e = new Error("EACCES: permission denied, open '~/.mcpm/guard-policy.yaml'");
          (e as NodeJS.ErrnoException).code = "EACCES";
          throw e;
        },
      };
    });
    vi.doMock("../relay.js", async () => {
      const actual = await vi.importActual<typeof import("../relay.js")>("../relay.js");
      return {
        ...actual,
        startRelay: () => ({ child: {} as never, exit: Promise.resolve(0) }),
      };
    });

    const { runInner } = await import("../run-inner.js");
    const code = await runInner(runInnerArgs);
    expect(code).toBe(0); // fell back to full enforcement, relay started
    const stderr = stderrSpy.mock.calls.flat().join("");
    expect(stderr).toContain("[mcpm-guard] POLICY-READ-ERROR:");
    expect(stderr).toContain("EACCES");
    // Must NOT mislabel a generic I/O error as an integrity tamper.
    expect(stderr).not.toContain("POLICY-INTEGRITY-ERROR:");
    // The {} fallback is the safe state — do NOT fail closed.
    expect(exitSpy).not.toHaveBeenCalled();
  });
});
