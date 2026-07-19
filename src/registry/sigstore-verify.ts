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

function couldNotVerify(reason: string, san?: string, issuer?: string): NpmProvenanceVerification {
  return {
    outcome: "could-not-verify",
    reason,
    ...(san !== undefined ? { signerSan: san } : {}),
    ...(issuer !== undefined ? { signerIssuer: issuer } : {}),
  };
}

/** True iff the attestation subject's hex sha512 matches an sha512 entry in the SRI. */
function subjectBindsToIntegrity(hexSha512: string | undefined, sri: string): boolean {
  if (hexSha512 === undefined || !/^[0-9a-f]{128}$/i.test(hexSha512)) return false;
  const subjectB64 = Buffer.from(hexSha512, "hex").toString("base64");
  for (const token of sri.trim().split(/\s+/)) {
    const m = /^sha512-(.+)$/.exec(token);
    if (m && m[1] === subjectB64) return true;
  }
  return false;
}

/**
 * Verify an npm SLSA provenance bundle offline. Returns a verdict; NEVER throws.
 *
 * @param rawBundle  the matched attestation's `bundle` object (SLSA v1)
 * @param ctx.identity      the parsed identity (subjectDigestSha512 is the bind oracle)
 * @param ctx.integritySri  the package's dist.integrity SRI (H11 anchor)
 */
export function cryptoVerifySlsaBundle(
  rawBundle: unknown,
  ctx: { identity: ProvenanceIdentity; integritySri: string }
): NpmProvenanceVerification {
  try {
    const bundle = bundleFromJSON(rawBundle); // throws ValidationError on a bad shape
    // NO policy argument — the policy param is verified as an UNANCHORED regex
    // (an injection footgun). We do our own strict === checks below instead.
    const signer = getVerifier().verify(toSignedEntity(bundle)); // throws on any crypto failure
    const san = signer.identity?.subjectAlternativeName;
    const issuer = signer.identity?.extensions?.issuer;

    if (issuer !== GITHUB_OIDC_ISSUER) return couldNotVerify("issuer-not-github-actions", san, issuer);
    // Bind the crypto-verified payload to THIS package's published tarball.
    if (!subjectBindsToIntegrity(ctx.identity.subjectDigestSha512, ctx.integritySri)) {
      return couldNotVerify("subject-digest-mismatch", san, issuer);
    }
    return {
      outcome: "verified",
      ...(san !== undefined ? { signerSan: san } : {}),
      ...(issuer !== undefined ? { signerIssuer: issuer } : {}),
    };
  } catch (e) {
    // ANY failure → could-not-verify (fail-CLOSED). Record the error code for `why`.
    const code =
      (e as { code?: unknown })?.code ??
      (e as Error)?.constructor?.name ??
      "verify-error";
    return { outcome: "could-not-verify", reason: String(code).slice(0, 300) };
  }
}
