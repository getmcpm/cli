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

// Derive the REAL subject sha512 (hex) + the matching dist.integrity SRI from the
// fixture — the subject-binding oracle.
const payload = JSON.parse(Buffer.from(V1.bundle.dsseEnvelope.payload, "base64").toString("utf8"));
const subjectHex: string = payload.subject[0].digest.sha512;
const realSri = "sha512-" + Buffer.from(subjectHex, "hex").toString("base64");
const identity = { subjectDigestSha512: subjectHex } as Parameters<typeof cryptoVerifySlsaBundle>[1]["identity"];

const flipB64 = (b64: string, from: string, to: string): string =>
  Buffer.from(Buffer.from(b64, "base64").toString("utf8").replace(from, to)).toString("base64");

describe("cryptoVerifySlsaBundle — offline crypto verification", () => {
  it("VERIFIES the real bundle against the vendored trusted root, binds the subject digest", () => {
    const r = cryptoVerifySlsaBundle(V1.bundle, { identity, integritySri: realSri });
    expect(r.outcome).toBe("verified");
    expect(r.signerIssuer).toBe("https://token.actions.githubusercontent.com");
    expect(r.signerSan).toContain("github.com/getmcpm/cli");
  });

  it("REFUSES (subject-digest-mismatch) when the SRI does not match the attested subject", () => {
    const wrongSri = "sha512-" + Buffer.from("0".repeat(128), "hex").toString("base64");
    const r = cryptoVerifySlsaBundle(V1.bundle, { identity, integritySri: wrongSri });
    expect(r.outcome).toBe("could-not-verify");
    expect(r.reason).toBe("subject-digest-mismatch");
  });

  it("REFUSES when there is no subject digest to bind", () => {
    const r = cryptoVerifySlsaBundle(V1.bundle, { identity: {}, integritySri: realSri });
    expect(r.outcome).toBe("could-not-verify");
    expect(r.reason).toBe("subject-digest-mismatch");
  });

  it("REFUSES a tampered DSSE payload (tlog body hash mismatch), never throws", () => {
    const bad = structuredClone(V1.bundle);
    bad.dsseEnvelope.payload = flipB64(bad.dsseEnvelope.payload, "getmcpm", "evilpkg");
    const r = cryptoVerifySlsaBundle(bad, { identity, integritySri: realSri });
    expect(r.outcome).toBe("could-not-verify");
  });

  it("REFUSES a tampered signature, never throws", () => {
    const bad = structuredClone(V1.bundle);
    const sig: string = bad.dsseEnvelope.signatures[0].sig;
    // Flip the last base64 char to a different valid one.
    bad.dsseEnvelope.signatures[0].sig = sig.slice(0, -2) + (sig.slice(-2, -1) === "A" ? "B" : "A") + "=";
    const r = cryptoVerifySlsaBundle(bad, { identity, integritySri: realSri });
    expect(r.outcome).toBe("could-not-verify");
  });

  it("REFUSES a malformed bundle (bundleFromJSON throws), never throws", () => {
    expect(cryptoVerifySlsaBundle({}, { identity, integritySri: realSri }).outcome).toBe("could-not-verify");
    expect(cryptoVerifySlsaBundle(null, { identity, integritySri: realSri }).outcome).toBe("could-not-verify");
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
