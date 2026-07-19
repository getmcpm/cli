import { readFileSync } from "node:fs";
import { describe, it, expect } from "vitest";
import {
  fetchNpmProvenance,
  compareProvenance,
  type NpmProvenanceSnapshot,
} from "./npm-provenance.js";

// Real captured attestation of @getmcpm/cli@0.21.0 (dogfood fixture).
const REAL = JSON.parse(
  readFileSync(new URL("./__fixtures__/attestations-getmcpm-cli.json", import.meta.url), "utf-8")
);

function mockResponse(opts: {
  status?: number;
  type?: string;
  json?: unknown;
  contentLength?: number;
}): Response {
  const status = opts.status ?? 200;
  return {
    status,
    ok: status >= 200 && status < 300,
    type: opts.type ?? "basic",
    headers: {
      get: (k: string) =>
        k.toLowerCase() === "content-length" && opts.contentLength !== undefined
          ? String(opts.contentLength)
          : null,
    },
    json: async () => opts.json,
    body: undefined,
  } as unknown as Response;
}

const fetchReturning = (r: Response): typeof fetch => (async () => r) as unknown as typeof fetch;
const fetchThrowing = (): typeof fetch =>
  (async () => {
    throw new Error("network");
  }) as unknown as typeof fetch;

function b64(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString("base64");
}

// Build an attestations response with a synthetic SLSA v1 predicate.
function v1Response(over: { repository?: string; repositoryId?: string; ownerId?: string; path?: string } = {}) {
  return {
    attestations: [
      {
        predicateType: "https://slsa.dev/provenance/v1",
        bundle: {
          dsseEnvelope: {
            payload: b64({
              subject: [{ digest: { sha512: "abc" } }],
              predicate: {
                buildDefinition: {
                  externalParameters: { workflow: { repository: over.repository, path: over.path, ref: "refs/tags/v1" } },
                  internalParameters: { github: { repository_id: over.repositoryId, repository_owner_id: over.ownerId } },
                  resolvedDependencies: [{ digest: { gitCommit: "deadbeef" } }],
                },
                runDetails: { builder: { id: "https://github.com/actions/runner" } },
              },
            }),
          },
        },
      },
    ],
  };
}

describe("fetchNpmProvenance — TRI-STATE (network blip must NOT read as a rug-pull)", () => {
  const call = (f: typeof fetch) => fetchNpmProvenance("@scope/pkg", "1.2.3", { fetchImpl: f });

  it("a definitive 404 → unsigned (the ONLY path to unsigned)", async () => {
    const r = await call(fetchReturning(mockResponse({ status: 404, json: { error: "Not found" } })));
    expect(r).toEqual({ npmVersion: "1.2.3", status: "unsigned", mode: "registry-record" });
  });

  it("5xx / network / abort → undefined (fail-open, NOT unsigned)", async () => {
    expect(await call(fetchReturning(mockResponse({ status: 503, json: {} })))).toBeUndefined();
    expect(await call(fetchThrowing())).toBeUndefined();
  });

  it("a redirect is refused → undefined (never an attacker host)", async () => {
    expect(await call(fetchReturning(mockResponse({ type: "opaqueredirect", status: 0 })))).toBeUndefined();
    expect(await call(fetchReturning(mockResponse({ status: 302, json: {} })))).toBeUndefined();
  });

  it("oversize body (declared content-length past the cap) → undefined", async () => {
    const r = await call(fetchReturning(mockResponse({ json: REAL, contentLength: 5 * 1024 * 1024 })));
    expect(r).toBeUndefined();
  });

  it("200 with an unknown/unparseable shape → unsupported (fail-CLOSED vocabulary)", async () => {
    expect((await call(fetchReturning(mockResponse({ json: {} })))!).status).toBe("unsupported");
    expect(
      (await call(fetchReturning(mockResponse({ json: { attestations: [{ predicateType: "other" }] } })))!)
        .status
    ).toBe("unsupported");
  });
});

describe("fetchNpmProvenance — parse-only identity extraction", () => {
  it("extracts the identity tuple from the real @getmcpm/cli attestation (no crypto)", async () => {
    const r = await fetchNpmProvenance("@getmcpm/cli", "0.21.0", {
      fetchImpl: fetchReturning(mockResponse({ json: REAL })),
    });
    expect(r?.status).toBe("attested");
    expect(r?.identity).toMatchObject({
      sourceRepo: "https://github.com/getmcpm/cli",
      repositoryId: "1194736883",
      repositoryOwnerId: "271823931",
      workflowPath: ".github/workflows/publish.yml",
      predicateType: "https://slsa.dev/provenance/v1",
    });
    expect(r?.identity?.commitSha).toMatch(/^[0-9a-f]{40}$/);
    expect(r?.identity?.subjectDigestSha512).toBeTruthy();
  });

  it("handles the legacy SLSA v0.2 shape (repo derived from configSource.uri)", async () => {
    const v02 = {
      attestations: [
        {
          predicateType: "https://slsa.dev/provenance/v0.2",
          bundle: {
            dsseEnvelope: {
              payload: b64({
                subject: [{ digest: { sha512: "deadbeef" } }],
                predicate: {
                  invocation: { configSource: { uri: "git+https://github.com/owner/repo@refs/tags/v1" } },
                  builder: { id: "https://github.com/actions/runner" },
                },
              }),
            },
          },
        },
      ],
    };
    const r = await fetchNpmProvenance("owner-repo", "1.0.0", {
      fetchImpl: fetchReturning(mockResponse({ json: v02 })),
    });
    expect(r?.status).toBe("attested");
    expect(r?.identity?.sourceRepo).toBe("https://github.com/owner/repo");
    expect(r?.identity?.repositoryId).toBeUndefined(); // v0.2 has no numeric ids
  });

  it("an over-cap field → unsupported (must never write a lock its own schema rejects)", async () => {
    const overcap = v1Response({ repository: "https://github.com/a/b", repositoryId: "1".repeat(100) }); // cap 64
    const r = await fetchNpmProvenance("a-b", "1.0.0", { fetchImpl: fetchReturning(mockResponse({ json: overcap })) });
    expect(r?.status).toBe("unsupported");
    expect(r?.identity).toBeUndefined();
  });

  it("an anchorless attestation (no repo id AND no source repo) → unsupported, not a hollow attested", async () => {
    const anchorless = v1Response({ path: ".github/workflows/x.yml" }); // no repository, no repository_id
    const r = await fetchNpmProvenance("x", "1.0.0", { fetchImpl: fetchReturning(mockResponse({ json: anchorless })) });
    expect(r?.status).toBe("unsupported");
  });
});

describe("compareProvenance — drift classifier (report-only)", () => {
  const snap = (over: Partial<NpmProvenanceSnapshot> = {}): NpmProvenanceSnapshot => ({
    npmVersion: "1.0.0",
    status: "attested",
    mode: "registry-record",
    identity: { repositoryId: "1", repositoryOwnerId: "9", sourceRepo: "https://github.com/a/b" },
    ...over,
  });

  it("returns none when there is nothing to compare", () => {
    expect(compareProvenance(undefined, snap())).toBe("none"); // no baseline
    expect(compareProvenance(snap(), undefined)).toBe("none"); // fail-open this run
    expect(compareProvenance(snap({ status: "unsigned", identity: undefined }), snap())).toBe("none"); // baseline not attested
    expect(compareProvenance(snap(), snap({ status: "unsupported", identity: undefined }))).toBe("none");
  });

  it("attested → unsigned is the signed-to-unsigned drop", () => {
    expect(compareProvenance(snap(), snap({ status: "unsigned", identity: undefined }))).toBe("signed-to-unsigned");
  });

  it("a changed numeric repo/owner id is identity-drift", () => {
    expect(compareProvenance(snap(), snap({ identity: { repositoryId: "2", repositoryOwnerId: "9" } }))).toBe("identity-drift");
    expect(compareProvenance(snap(), snap({ identity: { repositoryId: "1", repositoryOwnerId: "8" } }))).toBe("identity-drift");
  });

  it("a stable numeric id is NOT drift even if the URL/workflow changed (repo rename)", () => {
    const renamed = snap({ identity: { repositoryId: "1", repositoryOwnerId: "9", sourceRepo: "https://github.com/a/RENAMED" } });
    expect(compareProvenance(snap(), renamed)).toBe("none");
  });

  it("an asymmetrically-absent owner id (stable repo id) is NOT drift", () => {
    const withOwner = snap({ identity: { repositoryId: "1", repositoryOwnerId: "9" } });
    const noOwner = snap({ identity: { repositoryId: "1" } }); // owner id absent this run
    expect(compareProvenance(withOwner, noOwner)).toBe("none");
    expect(compareProvenance(noOwner, withOwner)).toBe("none");
  });

  it("falls back to normalized source repo when numeric ids are absent (legacy)", () => {
    const a = snap({ identity: { sourceRepo: "https://github.com/a/b.git" } });
    const same = snap({ identity: { sourceRepo: "https://github.com/a/b" } }); // .git normalized away
    const other = snap({ identity: { sourceRepo: "https://github.com/evil/b" } });
    expect(compareProvenance(a, same)).toBe("none");
    expect(compareProvenance(a, other)).toBe("identity-drift");
  });
});

describe("fetchNpmProvenance — crypto verification wiring (F8 crypto slice)", () => {
  // Derive the REAL dist.integrity SRI from the fixture's SLSA-v1 subject digest.
  const v1 = REAL.attestations.find((a: { predicateType: string }) => a.predicateType === "https://slsa.dev/provenance/v1");
  const subjectHex = JSON.parse(Buffer.from(v1.bundle.dsseEnvelope.payload, "base64").toString("utf-8")).subject[0].digest.sha512;
  const realSri = "sha512-" + Buffer.from(subjectHex, "hex").toString("base64");
  const serveReal = fetchReturning(mockResponse({ json: REAL }));

  it("attaches a VERIFIED verdict when integritySri subject-binds the attestation", async () => {
    const r = await fetchNpmProvenance("@getmcpm/cli", "0.21.0", { fetchImpl: serveReal, integritySri: realSri });
    expect(r?.status).toBe("attested"); // status never changes — additive
    expect(r?.verification?.outcome).toBe("verified");
    expect(r?.verification?.signerIssuer).toBe("https://token.actions.githubusercontent.com");
  });

  it("a wrong SRI records could-not-verify but KEEPS the attested snapshot (no erase)", async () => {
    const r = await fetchNpmProvenance("@getmcpm/cli", "0.21.0", { fetchImpl: serveReal, integritySri: "sha512-" + "A".repeat(88) });
    expect(r?.status).toBe("attested");
    expect(r?.verification?.outcome).toBe("could-not-verify");
    expect(r?.identity?.repositoryId).toBe("1194736883"); // parse-only identity intact
  });

  it("no integritySri → no crypto attempt, snapshot stays parse-only (verification absent)", async () => {
    const r = await fetchNpmProvenance("@getmcpm/cli", "0.21.0", { fetchImpl: serveReal });
    expect(r?.status).toBe("attested");
    expect(r?.verification).toBeUndefined();
  });
})
