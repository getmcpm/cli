/**
 * npm provenance-identity tripwire (F8 slice 1 — parse-only, WARN-only).
 *
 * Fetches npm's published Sigstore attestation bundle for an exact package
 * coordinate and extracts the build-identity tuple (source repo + the immutable
 * numeric GitHub repository/owner ids + workflow + commit) by PARSING the
 * attestation JSON — NO cryptographic verification, NO new dependencies. This
 * lets `mcpm lock` detect provenance-IDENTITY DRIFT: the pipeline/repo identity
 * behind a package changing across versions, or a signed package going unsigned
 * — the Postmark republish shape that schema-pinning structurally cannot see.
 *
 * HONESTY BOUNDARY (enforced in review): this checks npm's PUBLISHED attestation
 * RECORD, fetched over TLS from a hard-coded host — the same anchor the H11
 * dist.integrity tripwire already trusts. It is tamper-EVIDENCE, NOT
 * cryptographic proof: this slice NEVER says "verified" (that word is reserved
 * for the future @sigstore crypto slice) and NEVER feeds the trust score.
 * "attested" means an UNVERIFIED registry record; it reflects build IDENTITY,
 * not safety, and cannot catch a same-repo CI compromise that produces a valid
 * attestation with an unchanged identity (the TanStack lesson).
 */

import type { NpmProvenanceSnapshot, ProvenanceIdentity } from "../stack/schema.js";
import { NpmProvenanceSnapshotSchema } from "../stack/schema.js";

export type { NpmProvenanceSnapshot, ProvenanceIdentity } from "../stack/schema.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Hard-coded npm registry host — not caller-overridable (SSRF prevention). */
const NPM_REGISTRY_HOST = "registry.npmjs.org";

/** Attestation bundle body cap. A real bundle is ~15 KB; 2 MB is generous. */
const BODY_CAP_BYTES = 2 * 1024 * 1024; // 2 MB

/** Default HTTP timeout. */
const DEFAULT_TIMEOUT_MS = 5_000;

/** SLSA provenance predicate types we know how to parse (v1 current, v0.2 legacy). */
const SLSA_V1 = "https://slsa.dev/provenance/v1";
const SLSA_V02 = "https://slsa.dev/provenance/v0.2";

// ---------------------------------------------------------------------------
// fetchNpmProvenance — TRI-STATE (load-bearing zero-FP defense)
// ---------------------------------------------------------------------------

/**
 * Fetch and parse npm's attestation record for an exact package coordinate.
 *
 * TRI-STATE (the distinction is the whole point — a network blip must NEVER be
 * mistaken for a signed→unsigned rug-pull):
 *   - a DEFINITIVE 404 → `{ status: "unsigned" }` (no attestations for a
 *     resolved coordinate; the caller only asks for packages it just resolved)
 *   - 200 with a parseable SLSA attestation carrying a comparable anchor →
 *     `{ status: "attested", identity }`
 *   - 200 with valid JSON but no recognizable/comparable SLSA attestation, or a
 *     record that violates its own snapshot caps → `{ status: "unsupported" }`
 *   - ANYTHING ELSE (5xx, timeout, redirect, oversize, malformed/non-JSON body,
 *     network error) → `undefined` = FAIL-OPEN, deliberately distinct from "unsigned"
 *
 * The host is hard-coded and HTTPS is guaranteed by the literal URL; redirects
 * are refused (`redirect: "manual"`). NEVER throws.
 */
export async function fetchNpmProvenance(
  identifier: string,
  npmVersion: string,
  opts?: { fetchImpl?: typeof fetch; timeoutMs?: number }
): Promise<NpmProvenanceSnapshot | undefined> {
  const fetchImpl = opts?.fetchImpl ?? fetch;
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  try {
    // encodeURIComponent the whole "<name>@<version>" spec (verified: the fully
    // percent-encoded form resolves at this endpoint), so a crafted name/version
    // cannot escape the path segment. Inside the try so a URIError (lone
    // surrogate) also fails-open rather than throwing (honors "NEVER throws").
    const spec = encodeURIComponent(`${identifier}@${npmVersion}`);
    const url = `https://${NPM_REGISTRY_HOST}/-/npm/v1/attestations/${spec}`;

    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await fetchImpl(url, { redirect: "manual", signal: controller.signal });
    } catch {
      return undefined; // network error / abort → fail-open
    } finally {
      clearTimeout(timerId);
    }

    // A definitive 404 is the ONLY path to "unsigned".
    if (response.status === 404) {
      return { npmVersion, status: "unsigned", mode: "registry-record" };
    }
    // Refuse redirects and any other non-2xx → fail-open (NOT unsigned).
    if (response.type === "opaqueredirect") return undefined;
    if (response.status >= 300 && response.status < 400) return undefined;
    if (!response.ok) return undefined;

    const raw = await readCappedJson(response);
    if (raw === undefined) return undefined; // oversize / unreadable body → fail-open

    const identity = extractIdentity(raw);
    // 200 with a body we cannot map to a known+comparable SLSA attestation →
    // unsupported (fail-CLOSED vocabulary — an unknown/anchorless shape must
    // never read as "attested").
    if (identity === undefined) {
      return { npmVersion, status: "unsupported", mode: "registry-record" };
    }
    // Validate the UNVERIFIED, registry-derived snapshot against its own caps
    // BEFORE it can reach the lock. An over-cap/malformed field is by definition
    // not a supported attestation shape, and would otherwise write a lock that
    // parseLockFile (safeParse) later THROWS on — bricking up/verify/diff. So an
    // over-cap record degrades to "unsupported" rather than a poisoned lock.
    const snap: NpmProvenanceSnapshot = {
      npmVersion,
      status: "attested",
      mode: "registry-record",
      identity,
    };
    const parsed = NpmProvenanceSnapshotSchema.safeParse(snap);
    return parsed.success
      ? parsed.data
      : { npmVersion, status: "unsupported", mode: "registry-record" };
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Capped body reader (mirrors npm-integrity.ts)
// ---------------------------------------------------------------------------

async function readCappedJson(response: Response): Promise<unknown> {
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined) {
    const len = Number(declared);
    if (Number.isFinite(len) && len > BODY_CAP_BYTES) return undefined;
  }
  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const text = await readCappedStream(body);
    if (text === undefined) return undefined;
    try {
      return JSON.parse(text);
    } catch {
      return undefined;
    }
  }
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

async function readCappedStream(body: ReadableStream<Uint8Array>): Promise<string | undefined> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > BODY_CAP_BYTES) return undefined;
        chunks.push(value);
      }
    }
  } catch {
    return undefined;
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(out);
}

// ---------------------------------------------------------------------------
// Parse-only identity extraction (JSON + base64 only — no crypto, no ASN.1)
// ---------------------------------------------------------------------------

function asObject(v: unknown): Record<string, unknown> | undefined {
  return v !== null && typeof v === "object" ? (v as Record<string, unknown>) : undefined;
}
function asString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

/**
 * Extract the build-identity tuple from an attestations response, or undefined
 * if no recognizable SLSA provenance attestation is present (→ "unsupported").
 */
function extractIdentity(raw: unknown): ProvenanceIdentity | undefined {
  const root = asObject(raw);
  const atts = root?.attestations;
  if (!Array.isArray(atts)) return undefined;

  for (const att of atts) {
    const attObj = asObject(att);
    const predicateType = asString(attObj?.predicateType);
    if (predicateType !== SLSA_V1 && predicateType !== SLSA_V02) continue;

    const dsse = asObject(asObject(attObj?.bundle)?.dsseEnvelope);
    const payloadB64 = asString(dsse?.payload);
    if (payloadB64 === undefined) continue;

    let statement: Record<string, unknown> | undefined;
    try {
      statement = asObject(JSON.parse(Buffer.from(payloadB64, "base64").toString("utf-8")));
    } catch {
      continue;
    }
    if (statement === undefined) continue;

    const identity =
      predicateType === SLSA_V1
        ? extractSlsaV1(statement)
        : extractSlsaV02(statement);
    // Require at least one COMPARABLE anchor (immutable numeric repo id or the
    // source repo URL). An anchorless payload could never drift-compare, so it
    // must not read as a hollow "attested" — fall through to the next
    // attestation and ultimately to "unsupported".
    if (
      identity !== undefined &&
      (identity.repositoryId !== undefined || identity.sourceRepo !== undefined)
    ) {
      return { ...identity, predicateType, subjectDigestSha512: subjectSha512(statement) };
    }
  }
  return undefined;
}

/** SLSA v1 (current npm/GitHub format) — the immutable numeric ids live here. */
function extractSlsaV1(statement: Record<string, unknown>): Omit<ProvenanceIdentity, "predicateType" | "subjectDigestSha512"> | undefined {
  const bd = asObject(asObject(statement.predicate)?.buildDefinition);
  if (bd === undefined) return undefined;
  const workflow = asObject(asObject(bd.externalParameters)?.workflow);
  const github = asObject(asObject(bd.internalParameters)?.github);
  const runDetails = asObject(asObject(statement.predicate)?.runDetails);
  const deps = bd.resolvedDependencies;
  const firstDep = Array.isArray(deps) ? asObject(deps[0]) : undefined;
  return {
    sourceRepo: asString(workflow?.repository),
    workflowPath: asString(workflow?.path),
    workflowRef: asString(workflow?.ref),
    repositoryId: asString(github?.repository_id),
    repositoryOwnerId: asString(github?.repository_owner_id),
    builderId: asString(asObject(runDetails?.builder)?.id),
    commitSha: asString(asObject(firstDep?.digest)?.gitCommit),
  };
}

/** SLSA v0.2 (legacy) — no numeric ids; derive the repo from configSource.uri. */
function extractSlsaV02(statement: Record<string, unknown>): Omit<ProvenanceIdentity, "predicateType" | "subjectDigestSha512"> | undefined {
  const predicate = asObject(statement.predicate);
  const configSource = asObject(asObject(predicate?.invocation)?.configSource);
  const uri = asString(configSource?.uri); // e.g. "git+https://github.com/owner/repo@refs/tags/v1"
  if (uri === undefined) return undefined;
  const at = uri.lastIndexOf("@");
  const repo = at > 0 ? uri.slice(0, at) : uri;
  return {
    sourceRepo: repo.replace(/^git\+/, ""),
    workflowRef: at > 0 ? uri.slice(at + 1) : undefined,
    builderId: asString(asObject(predicate?.builder)?.id),
  };
}

function subjectSha512(statement: Record<string, unknown>): string | undefined {
  const subjects = statement.subject;
  if (!Array.isArray(subjects)) return undefined;
  for (const s of subjects) {
    const digest = asObject(asObject(s)?.digest);
    const sha512 = asString(digest?.sha512);
    if (sha512 !== undefined) return sha512;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// compareProvenance — the drift classifier (report-only; never blocks)
// ---------------------------------------------------------------------------

/**
 * Drift verdict between a previously-locked snapshot and a freshly-fetched one.
 *   - "identity-drift"     — the build pipeline's repo/owner identity changed
 *   - "signed-to-unsigned" — a package that WAS attested is now unsigned
 *   - "none"               — same identity, an improvement, or not comparable
 *
 * ZERO-FP tiering: comparison prefers the IMMUTABLE numeric repository/owner ids
 * (they survive repo renames), falling back to the source-repo URL only when a
 * legacy snapshot lacks them. A URL/workflow/ref change with a stable numeric id
 * is a cosmetic rename → "none". All verdicts are advisory (org transfers
 * legitimately change the owner id), so callers WARN, never block.
 */
export type ProvenanceDrift = "none" | "identity-drift" | "signed-to-unsigned";

export function compareProvenance(
  prev: NpmProvenanceSnapshot | undefined,
  next: NpmProvenanceSnapshot | undefined
): ProvenanceDrift {
  // No fresh reading (fail-open) or no baseline → nothing to compare.
  if (next === undefined || prev === undefined) return "none";
  // Only an ATTESTED baseline can drift; unsigned→attested is an improvement.
  if (prev.status !== "attested") return "none";

  if (next.status === "unsigned") return "signed-to-unsigned";
  if (next.status !== "attested") return "none"; // unsupported this run → not comparable

  return identityChanged(prev.identity, next.identity) ? "identity-drift" : "none";
}

function normRepo(url: string | undefined): string | undefined {
  return url?.trim().toLowerCase().replace(/\/+$/, "").replace(/\.git$/, "");
}

function identityChanged(
  a: ProvenanceIdentity | undefined,
  b: ProvenanceIdentity | undefined
): boolean {
  if (a === undefined || b === undefined) return false; // can't tell → not a drift
  // Prefer immutable numeric ids (survive repo renames / org display changes).
  if (a.repositoryId !== undefined && b.repositoryId !== undefined) {
    // Compare owner ids only when BOTH are present — an asymmetrically-absent
    // owner id (one snapshot has it, the other doesn't) is a shape difference,
    // not an ownership change, so it must not false-positive as drift.
    const ownerChanged =
      a.repositoryOwnerId !== undefined &&
      b.repositoryOwnerId !== undefined &&
      a.repositoryOwnerId !== b.repositoryOwnerId;
    return a.repositoryId !== b.repositoryId || ownerChanged;
  }
  // Fallback for legacy snapshots without numeric ids: normalized source repo.
  const ra = normRepo(a.sourceRepo);
  const rb = normRepo(b.sourceRepo);
  if (ra === undefined || rb === undefined) return false; // insufficient info → not a drift
  return ra !== rb;
}
