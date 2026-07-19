import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, it, expect } from "vitest";
import { cryptoVerifySlsaBundle } from "./sigstore-verify.js";

// The real captured @getmcpm/cli@0.21.0 attestation (dogfood fixture).
const fixture = JSON.parse(
  readFileSync(new URL("./__fixtures__/attestations-getmcpm-cli.json", import.meta.url), "utf8")
);
const V1 = fixture.attestations.find(
  (a: { predicateType: string }) => a.predicateType === "https://slsa.dev/provenance/v1"
);

// Derive the REAL dist.integrity SRI from the fixture's verified subject digest.
const payload = JSON.parse(Buffer.from(V1.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
const subjectHex: string = payload.subject[0].digest.sha512;
const realSri = "sha512-" + Buffer.from(subjectHex, "hex").toString("base64");

const flipB64 = (b64: string, from: string, to: string): string =>
  Buffer.from(Buffer.from(b64, "base64").toString("utf8").replace(from, to)).toString("base64");

describe("cryptoVerifySlsaBundle — offline crypto verification", () => {
  it("VERIFIES the real bundle offline; subject bound from the VERIFIED payload, identity from the SAN", () => {
    const r = cryptoVerifySlsaBundle(V1.bundle, { integritySri: realSri });
    expect(r.verification.outcome).toBe("verified");
    expect(r.verification.signerIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(r.verification.signerSan).toContain("github.com/getmcpm/cli");
    // The trusted identity comes from the UNFORGEABLE cert SAN, NOT the payload.
    expect(r.verifiedIdentity?.sourceRepo).toBe("https://github.com/getmcpm/cli");
    expect(r.verifiedIdentity?.workflowPath).toBe(".github/workflows/publish.yml");
  });

  it("REFUSES (subject-digest-mismatch) when the target SRI ≠ the VERIFIED payload's subject", () => {
    const wrongSri = "sha512-" + Buffer.from("0".repeat(128), "hex").toString("base64");
    const r = cryptoVerifySlsaBundle(V1.bundle, { integritySri: wrongSri });
    expect(r.verification.outcome).toBe("could-not-verify");
    expect(r.verification.reason).toBe("subject-digest-mismatch");
    expect(r.verifiedIdentity).toBeUndefined();
  });

  it("REFUSES a multi-token SRI unless EVERY sha512 entry is the attested digest (ssri any-match seam)", () => {
    // Attacker SRI: token 1 = the attested (legit) digest; token 2 = a different
    // digest that npm's strongest-algo check would also accept for a swapped tarball.
    const otherB64 = Buffer.from("ab".repeat(64), "hex").toString("base64");
    const r = cryptoVerifySlsaBundle(V1.bundle, { integritySri: `${realSri} sha512-${otherB64}` });
    expect(r.verification.outcome).toBe("could-not-verify");
    expect(r.verification.reason).toBe("subject-digest-mismatch");
  });

  it("REFUSES a tampered DSSE payload (tlog body hash mismatch), never throws", () => {
    const bad = structuredClone(V1.bundle);
    bad.dsseEnvelope.payload = flipB64(bad.dsseEnvelope.payload, "getmcpm", "evilpkg");
    expect(cryptoVerifySlsaBundle(bad, { integritySri: realSri }).verification.outcome).toBe("could-not-verify");
  });

  it("REFUSES a tampered signature, never throws", () => {
    const bad = structuredClone(V1.bundle);
    const sig: string = bad.dsseEnvelope.signatures[0].sig;
    bad.dsseEnvelope.signatures[0].sig = sig.slice(0, -2) + (sig.slice(-2, -1) === "A" ? "B" : "A") + "=";
    expect(cryptoVerifySlsaBundle(bad, { integritySri: realSri }).verification.outcome).toBe("could-not-verify");
  });

  it("REFUSES a malformed bundle (bundleFromJSON throws), never throws", () => {
    expect(cryptoVerifySlsaBundle({}, { integritySri: realSri }).verification.outcome).toBe("could-not-verify");
    expect(cryptoVerifySlsaBundle(null, { integritySri: realSri }).verification.outcome).toBe("could-not-verify");
  });
});

describe("vendored trusted root — tamper tripwire", () => {
  it("matches the authenticity-verified sha256 (fails loudly if the vendored bytes change)", () => {
    const bytes = readFileSync(new URL("./sigstore-trusted-root.json", import.meta.url));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66"
    );
  });
});
