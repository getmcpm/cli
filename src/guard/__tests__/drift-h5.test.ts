/**
 * H5 — initialize-handshake drift detection (capabilities + identity).
 *
 * Pins the MCP `initialize` result's declared capabilities + serverInfo.name and
 * WARNS (never blocks — blocking an initialize result kills the session) when
 * either changes since first observed (TOFU). `instructions` and
 * `serverInfo.version` are DELIBERATELY out of scope.
 *
 * These tests cover the pure classifier (capability ADD/REMOVE, identity, both),
 * the warn-tier finding shapes + "since first observed" remediation copy, the
 * async first-session capture, the no-auto-re-pin durability rule, and the
 * warn-once previous_hashes dedup.
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import {
  classifyHandshakeDrift,
  buildHandshakeDriftFinding,
  inspectHandshakeForDrift,
  type HandshakeDriftClass,
  type HandshakeDriftDeps,
} from "../drift.js";
import {
  emptyPinsFile,
  handshakeFieldHashesOf,
  hashHandshake,
  upsertHandshakePin,
  type HandshakePinEntry,
  type PinsFile,
} from "../pins.js";
import { defaultActionForFinding } from "../patterns.js";

const SIGV = "v0.5.0";

const initializeMsg = (result: {
  capabilities?: unknown;
  serverInfo?: { name?: unknown; version?: unknown };
}): JSONRPCMessage =>
  ({
    jsonrpc: "2.0",
    id: 1,
    result: { protocolVersion: "2024-11-05", ...result },
  }) as JSONRPCMessage;

const handshakePin = (result: {
  capabilities?: unknown;
  serverInfo?: { name?: unknown };
}): HandshakePinEntry => {
  const fields = handshakeFieldHashesOf(result);
  return {
    current_hash: hashHandshake(fields),
    previous_hashes: [],
    captured_at: "2026-06-14T00:00:00Z",
    captured_via: "first-session",
    signature_list_version: SIGV,
    field_hashes: fields,
    capability_keys:
      result.capabilities !== null && typeof result.capabilities === "object"
        ? Object.keys(result.capabilities as Record<string, unknown>).sort()
        : [],
  };
};

function makeDeps(initialPins: PinsFile): { deps: HandshakeDriftDeps; writes: PinsFile[] } {
  const writes: PinsFile[] = [];
  let snapshot = initialPins;
  return {
    writes,
    deps: {
      read: async () => snapshot,
      write: async (p) => {
        writes.push(p);
        snapshot = p;
      },
      signatureListVersion: SIGV,
    },
  };
}

// ─────────────────────── classifyHandshakeDrift ───────────────────────

describe("classifyHandshakeDrift (H5)", () => {
  const pinned = handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });

  test("capability ADD (sampling) → kind capability, addedCaps [sampling]", () => {
    const live = { capabilities: { tools: {}, sampling: {} }, serverInfo: { name: "fs" } };
    const cls = classifyHandshakeDrift(
      pinned,
      handshakeFieldHashesOf(live),
      ["sampling", "tools"],
    );
    expect(cls.kind).toBe("capability");
    expect(cls.addedCaps).toEqual(["sampling"]);
    expect(cls.removedCaps).toEqual([]);
    expect(cls.identityChanged).toBe(false);
  });

  test("capability REMOVE → kind capability, removedCaps names the dropped key", () => {
    const richPin = handshakePin({
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: "fs" },
    });
    const live = { capabilities: { tools: {} }, serverInfo: { name: "fs" } };
    const cls = classifyHandshakeDrift(richPin, handshakeFieldHashesOf(live), ["tools"]);
    expect(cls.kind).toBe("capability");
    expect(cls.addedCaps).toEqual([]);
    expect(cls.removedCaps).toEqual(["resources"]);
  });

  test("identity change → kind identity", () => {
    const live = { capabilities: { tools: {} }, serverInfo: { name: "evil" } };
    const cls = classifyHandshakeDrift(pinned, handshakeFieldHashesOf(live), ["tools"]);
    expect(cls.kind).toBe("identity");
    expect(cls.identityChanged).toBe(true);
    expect(cls.addedCaps).toEqual([]);
    expect(cls.removedCaps).toEqual([]);
  });

  test("capability AND identity change → kind both", () => {
    const live = { capabilities: { tools: {}, sampling: {} }, serverInfo: { name: "evil" } };
    const cls = classifyHandshakeDrift(pinned, handshakeFieldHashesOf(live), ["sampling", "tools"]);
    expect(cls.kind).toBe("both");
    expect(cls.addedCaps).toEqual(["sampling"]);
    expect(cls.identityChanged).toBe(true);
  });
});

// ─────────────────────── buildHandshakeDriftFinding ───────────────────────

describe("buildHandshakeDriftFinding (H5)", () => {
  const safeServer = "fs";

  test("capability drift → warn-tier handshake-drift-capability, names added/removed", () => {
    const cls: HandshakeDriftClass = {
      kind: "capability",
      addedCaps: ["sampling"],
      removedCaps: ["resources"],
      identityChanged: false,
    };
    const findings = buildHandshakeDriftFinding({ cls, safeServer, liveWholeHash: "sha256:abc" });
    const cap = findings.find((f) => f.signature_id === "handshake-drift-capability");
    expect(cap).toBeDefined();
    expect(cap?.severity).toBe("high"); // high → warn (never block)
    expect(defaultActionForFinding(cap!)).toBe("warn");
    expect(cap?.category).toBe("OWASP-MCP-8");
    expect(cap?.matched_text_excerpt + cap?.remediation).toContain("sampling");
    expect(cap?.matched_text_excerpt + cap?.remediation).toContain("resources");
    // TOFU wording — never "since you approved".
    expect(cap?.remediation).toMatch(/first observed/i);
    expect(cap?.remediation).not.toMatch(/approved/i);
  });

  test("sampling/elicitation grant is flagged as an escalation in the message", () => {
    const cls: HandshakeDriftClass = {
      kind: "capability",
      addedCaps: ["elicitation"],
      removedCaps: [],
      identityChanged: false,
    };
    const findings = buildHandshakeDriftFinding({ cls, safeServer, liveWholeHash: "sha256:abc" });
    const cap = findings.find((f) => f.signature_id === "handshake-drift-capability");
    expect(cap?.remediation.toLowerCase()).toMatch(/grant|escalat/);
  });

  test("identity drift → warn-tier handshake-drift-identity, OWASP-MCP-1, impersonation copy", () => {
    const cls: HandshakeDriftClass = {
      kind: "identity",
      addedCaps: [],
      removedCaps: [],
      identityChanged: true,
    };
    const findings = buildHandshakeDriftFinding({ cls, safeServer, liveWholeHash: "sha256:abc" });
    const id = findings.find((f) => f.signature_id === "handshake-drift-identity");
    expect(id?.severity).toBe("high");
    expect(defaultActionForFinding(id!)).toBe("warn");
    expect(id?.category).toBe("OWASP-MCP-1");
    expect(id?.remediation.toLowerCase()).toMatch(/impersonat|serverinfo\.name|wrong binary/);
    expect(id?.remediation).toMatch(/first observed/i);
  });

  test("both → one finding per changed dimension", () => {
    const cls: HandshakeDriftClass = {
      kind: "both",
      addedCaps: ["sampling"],
      removedCaps: [],
      identityChanged: true,
    };
    const findings = buildHandshakeDriftFinding({ cls, safeServer, liveWholeHash: "sha256:abc" });
    const ids = findings.map((f) => f.signature_id);
    expect(ids).toContain("handshake-drift-capability");
    expect(ids).toContain("handshake-drift-identity");
    // NONE block — the whole point of H5.
    expect(findings.every((f) => defaultActionForFinding(f) === "warn")).toBe(true);
  });
});

// ─────────────────────── async first-session capture + dedup ───────────────────────

describe("inspectHandshakeForDrift (H5 async capture)", () => {
  test("first session: writes a first-session handshake pin (field_hashes + capability_keys) and passes", async () => {
    const { deps, writes } = makeDeps(emptyPinsFile());
    const msg = initializeMsg({
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: "fs", version: "1.0.0" },
    });
    const result = await inspectHandshakeForDrift(msg, "fs", deps);
    expect(result.action).toBe("pass");
    expect(writes).toHaveLength(1);
    const entry = writes[0]?.handshakes?.fs;
    expect(entry?.captured_via).toBe("first-session");
    expect(entry?.field_hashes).toBeDefined();
    expect(entry?.capability_keys).toEqual(["resources", "tools"]);
  });

  test("version-only bump vs pin → NO drift (pass), no write", async () => {
    const pins = upsertHandshakePin(
      emptyPinsFile(),
      "fs",
      handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
    );
    const { deps, writes } = makeDeps(pins);
    const msg = initializeMsg({
      capabilities: { tools: {} },
      serverInfo: { name: "fs", version: "2.0.0" },
    });
    const result = await inspectHandshakeForDrift(msg, "fs", deps);
    expect(result.action).toBe("pass");
    expect(writes).toHaveLength(0);
  });

  test("capability change → WARN (not block), handshake-drift-capability", async () => {
    const pins = upsertHandshakePin(
      emptyPinsFile(),
      "fs",
      handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
    );
    const { deps } = makeDeps(pins);
    const msg = initializeMsg({
      capabilities: { tools: {}, sampling: {} },
      serverInfo: { name: "fs" },
    });
    const result = await inspectHandshakeForDrift(msg, "fs", deps);
    expect(result.action).toBe("warn");
    expect(result.findings.map((f) => f.signature_id)).toContain("handshake-drift-capability");
  });

  test("identity change → WARN, handshake-drift-identity", async () => {
    const pins = upsertHandshakePin(
      emptyPinsFile(),
      "fs",
      handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
    );
    const { deps } = makeDeps(pins);
    const msg = initializeMsg({ capabilities: { tools: {} }, serverInfo: { name: "evil" } });
    const result = await inspectHandshakeForDrift(msg, "fs", deps);
    expect(result.action).toBe("warn");
    expect(result.findings.map((f) => f.signature_id)).toContain("handshake-drift-identity");
  });

  test("durability: the pin's current_hash is NOT moved on drift (no auto-re-pin)", async () => {
    const pins = upsertHandshakePin(
      emptyPinsFile(),
      "fs",
      handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
    );
    const before = pins.handshakes?.fs?.current_hash;
    const { deps, writes } = makeDeps(pins);
    const msg = initializeMsg({
      capabilities: { tools: {}, sampling: {} },
      serverInfo: { name: "fs" },
    });
    await inspectHandshakeForDrift(msg, "fs", deps);
    // If anything was written, current_hash must be unchanged (only previous_hashes appended).
    for (const w of writes) {
      expect(w.handshakes?.fs?.current_hash).toBe(before);
    }
  });

  test("warn-once: a live whole-hash already in previous_hashes → pass (already surfaced)", async () => {
    const base = handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } });
    const driftedLive = { capabilities: { tools: {}, sampling: {} }, serverInfo: { name: "fs" } };
    const driftedHash = hashHandshake(handshakeFieldHashesOf(driftedLive));
    // Pin already SURFACED the drifted hash in a prior session.
    const pins = upsertHandshakePin(emptyPinsFile(), "fs", {
      ...base,
      previous_hashes: [driftedHash],
    });
    const { deps } = makeDeps(pins);
    const result = await inspectHandshakeForDrift(initializeMsg(driftedLive), "fs", deps);
    expect(result.action).toBe("pass");
    expect(result.findings).toHaveLength(0);
  });

  test("on a NEW drift: appends the live whole-hash to previous_hashes (so next session dedups)", async () => {
    const pins = upsertHandshakePin(
      emptyPinsFile(),
      "fs",
      handshakePin({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
    );
    const { deps, writes } = makeDeps(pins);
    const driftedLive = { capabilities: { tools: {}, sampling: {} }, serverInfo: { name: "fs" } };
    const driftedHash = hashHandshake(handshakeFieldHashesOf(driftedLive));
    await inspectHandshakeForDrift(initializeMsg(driftedLive), "fs", deps);
    expect(writes).toHaveLength(1);
    expect(writes[0]?.handshakes?.fs?.previous_hashes).toContain(driftedHash);
  });

  test("PinsIntegrityError → fail-closed block (parity with tools/list arm)", async () => {
    const deps: HandshakeDriftDeps = {
      read: async () => {
        throw new PinsIntegrityErrorStub();
      },
      write: async () => undefined,
      signatureListVersion: SIGV,
    };
    const result = await inspectHandshakeForDrift(
      initializeMsg({ capabilities: { tools: {} }, serverInfo: { name: "fs" } }),
      "fs",
      deps,
    );
    expect(result.action).toBe("block");
    expect(result.findings[0]?.signature_id).toBe("pins-integrity-failure");
  });
});

// Local stub so the test does not import the real PinsIntegrityError into the
// classifier-only suite; drift.ts uses `instanceof PinsIntegrityError`, so this
// must be the real class — re-export it for the stub.
import { PinsIntegrityError } from "../pins.js";
class PinsIntegrityErrorStub extends PinsIntegrityError {
  constructor() {
    super("stub integrity failure");
  }
}
