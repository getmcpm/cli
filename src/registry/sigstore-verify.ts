/**
 * Offline cryptographic verification of an npm SLSA provenance bundle (F8 crypto
 * slice). This is the ONLY module in mcpm that may conclude "verified".
 *
 * Verifies the attestation's Sigstore bundle OFFLINE against a vendored
 * trusted_root.json — the bundle inlines the Rekor tlog entry + Fulcio cert
 * chain, so there is NO Rekor/Fulcio network call at verify time. Uses the four
 * audited @sigstore/* packages. All imports here are static, and this module is
 * only ever loaded via a dynamic `import()` from the caller's verify path — so
 * the ~940 KB of @sigstore + this trust material load ONLY when verification
 * actually runs; the default parse-only provenance path stays dependency-free.
 *
 * "verified" is granted ONLY when ALL hold:
 *   1. @sigstore/verify passes — DSSE signature + Fulcio chain + SCT threshold +
 *      Rekor tlog inclusion (offline, from the bundle + trusted root);
 *   2. the signer's OIDC issuer is GitHub Actions;
 *   3. the attestation's subject sha512 binds to the package's dist.integrity
 *      (the H11 anchor). @sigstore/verify checks the signature over the payload
 *      but NEVER that the payload's subject is THIS tarball — so without this
 *      bind a cryptographically valid attestation for ANOTHER package served at
 *      the same endpoint would read "verified". This gate is load-bearing.
 * ANY miss, or ANY throw (bundle parse / verification / trust material), yields
 * "could-not-verify". This module NEVER throws and NEVER fail-opens into a false
 * "verified".
 *
 * HONESTY: "verified" means the build IDENTITY is cryptographically attested by
 * the CI's OIDC token — NOT that the code is safe. A same-repo CI compromise
 * mints a valid attestation (the TanStack lesson). The signer SAN/issuer are
 * RECORDED, not gated on SAN-equality: a reusable workflow legitimately signs
 * from a different repo than the payload names, so hard-gating the SAN would be a
 * false negative. Drift on the payload identity tuple (slice 1) is what surfaces
 * a pipeline swap.
 */

import { bundleFromJSON } from "@sigstore/bundle";
import { toSignedEntity, toTrustMaterial, Verifier } from "@sigstore/verify";
import { TrustedRoot } from "@sigstore/protobuf-specs";
import trustedRootJson from "./sigstore-trusted-root.json" with { type: "json" };
import type { NpmProvenanceVerification, ProvenanceIdentity } from "../stack/schema.js";

const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

// Lazy singleton — building trust material parses the vendored root once per process.
let _verifier: Verifier | undefined;
function getVerifier(): Verifier {
  if (_verifier === undefined) {
    const trustMaterial = toTrustMaterial(TrustedRoot.fromJSON(trustedRootJson));
    _verifier = new Verifier(trustMaterial); // defaults: tlog=1, ctlog=1, timestamp=1
  }
  return _verifier;
}

// Fields are RECORDED not gated, so cap at source — an over-cap value must never
// fail the snapshot schema and degrade the whole attested record to "unsupported".
const cap = (s: string | undefined, n = 2048): string | undefined => s?.slice(0, n);

function couldNotVerify(reason: string, san?: string, issuer?: string): NpmProvenanceVerification {
  return {
    outcome: "could-not-verify",
    reason,
    ...(san !== undefined ? { signerSan: cap(san) } : {}),
    ...(issuer !== undefined ? { signerIssuer: cap(issuer) } : {}),
  };
}

/**
 * True iff the verified subject sha512 matches EVERY sha512 entry in the SRI (and
 * at least one). NOT any-match: npm/ssri enforces the STRONGEST algorithm present,
 * so a multi-token SRI `sha512-<A> sha512-<B>` could otherwise pass this bind on A
 * (a stolen genuine attestation's digest) while npm installs the tarball matching
 * B (the attacker's) — a false "verified" wearing the victim's identity. Pinning
 * every sha512 entry to the attested digest makes "verified" ⟹ the tarball npm
 * installs IS the attested one. Weaker-algo tokens are ignorable (ssri picks
 * sha512 when present); a sha512-less SRI fails closed.
 */
function subjectBindsToIntegrity(hexSha512: string | undefined, sri: string): boolean {
  if (hexSha512 === undefined || !/^[0-9a-f]{128}$/i.test(hexSha512)) return false;
  const subjectB64 = Buffer.from(hexSha512, "hex").toString("base64");
  const sha512Digests = sri
    .trim()
    .split(/\s+/)
    .map((t) => /^sha512-(.+)$/.exec(t)?.[1])
    .filter((d): d is string => d !== undefined);
  return sha512Digests.length > 0 && sha512Digests.every((d) => d === subjectB64);
}

/**
 * Read the subject sha512 (hex) from the CRYPTO-VERIFIED bundle's OWN DSSE payload.
 * `rawBundle.dsseEnvelope.payload` is the exact base64 that `bundleFromJSON` decoded
 * and `verify()` authenticated — so AFTER verify passes, this is verified data. The
 * subject must be derived from here, never from a value parsed out of a possibly
 * DIFFERENT attestation, or the crypto signature is decoupled from the tarball bind.
 */
function verifiedSubjectHex(rawBundle: unknown): string | undefined {
  const b64 = (rawBundle as { dsseEnvelope?: { payload?: unknown } })?.dsseEnvelope?.payload;
  if (typeof b64 !== "string") return undefined;
  try {
    const stmt = JSON.parse(Buffer.from(b64, "base64").toString("utf-8")) as {
      subject?: Array<{ digest?: { sha512?: unknown } }>;
    };
    if (!Array.isArray(stmt.subject)) return undefined;
    for (const s of stmt.subject) {
      if (typeof s?.digest?.sha512 === "string") return s.digest.sha512;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Derive the UNFORGEABLE build identity from the Fulcio cert SAN. The DSSE
 * payload's self-claimed repo / repository_id are attacker-forgeable — an
 * attacker signs an arbitrary statement (claiming any repo) with their OWN valid
 * GitHub-Actions OIDC cert. Only the cert SAN is bound to the real OIDC identity,
 * so a "verified" verdict's identity MUST come from here, not the payload.
 * SAN form: https://github.com/OWNER/REPO/.github/workflows/FILE@REF
 */
function parseSanIdentity(san: string | undefined): ProvenanceIdentity | undefined {
  if (san === undefined) return undefined;
  const m = /^(https:\/\/github\.com\/[^/]+\/[^/]+)\/(.+?)@([^@]+)$/.exec(san);
  if (m === null) return { sourceRepo: cap(san) }; // non-standard SAN — record verbatim (capped)
  return { sourceRepo: cap(m[1]), workflowPath: cap(m[2]), workflowRef: cap(m[3]) };
}

export interface CryptoResult {
  verification: NpmProvenanceVerification;
  /**
   * Present ONLY on "verified": the unforgeable SAN-derived identity. The caller
   * uses this as the snapshot identity so drift + display reflect the
   * cryptographically-attested signer — the parse-only payload tuple is a
   * self-claim and must not ride under a "verified" badge.
   */
  verifiedIdentity?: ProvenanceIdentity;
}

/**
 * Verify an npm SLSA provenance bundle offline. Returns a verdict; NEVER throws.
 *
 * @param rawBundle  the matched attestation's `bundle` object (SLSA v1)
 * @param ctx.integritySri  the package's dist.integrity SRI (H11 anchor)
 */
export function cryptoVerifySlsaBundle(
  rawBundle: unknown,
  ctx: { integritySri: string }
): CryptoResult {
  try {
    const bundle = bundleFromJSON(rawBundle); // throws ValidationError on a bad shape
    // NO policy argument — the policy param is verified as an UNANCHORED regex
    // (an injection footgun). We do our own strict === checks below instead.
    const signer = getVerifier().verify(toSignedEntity(bundle)); // throws on any crypto failure
    const san = signer.identity?.subjectAlternativeName;
    const issuer = signer.identity?.extensions?.issuer;

    if (issuer !== GITHUB_OIDC_ISSUER) {
      return { verification: couldNotVerify("issuer-not-github-actions", san, issuer) };
    }
    // Bind THIS package's tarball to the subject inside the CRYPTO-VERIFIED payload
    // — never a caller-supplied digest from a possibly-different attestation.
    if (!subjectBindsToIntegrity(verifiedSubjectHex(rawBundle), ctx.integritySri)) {
      return { verification: couldNotVerify("subject-digest-mismatch", san, issuer) };
    }
    // A GitHub-Actions OIDC cert always carries a SAN; if one is somehow absent we
    // CANNOT record an equality-checkable signer identity, so a downstream verify-time
    // gate would have nothing to compare. Refuse the "verified" verdict (fail closed)
    // rather than mint a SAN-less one that later reads as an un-checkable baseline.
    if (san === undefined) {
      return { verification: couldNotVerify("no-signer-san", san, issuer) };
    }
    return {
      verification: {
        outcome: "verified",
        ...(san !== undefined ? { signerSan: cap(san) } : {}),
        ...(issuer !== undefined ? { signerIssuer: cap(issuer) } : {}),
      },
      verifiedIdentity: parseSanIdentity(san),
    };
  } catch (e) {
    // ANY failure → could-not-verify (fail-CLOSED). Record the error code for `why`.
    const code =
      (e as { code?: unknown })?.code ??
      (e as Error)?.constructor?.name ??
      "verify-error";
    return { verification: { outcome: "could-not-verify", reason: String(code).slice(0, 300) } };
  }
}
