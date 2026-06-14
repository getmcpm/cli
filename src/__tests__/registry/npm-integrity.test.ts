/**
 * Unit tests for src/registry/npm-integrity.ts
 *
 * All tests are fully offline — fetchImpl is always injected (no real network).
 * Covers: happy path, URL encoding, all failure modes (FAIL-OPEN to undefined),
 * redirect handling, compareIntegrity logic.
 */

import { describe, it, expect, vi } from "vitest";
import {
  fetchNpmIntegrity,
  compareIntegrity,
} from "../../registry/npm-integrity.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal per-version npm registry response with dist.integrity. */
function makeNpmVersionResponse(integrity: string) {
  return {
    name: "test-pkg",
    version: "1.0.0",
    dist: {
      integrity,
      shasum: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  };
}

/** Build a fetch mock that returns a successful 200 with JSON body. */
function makeFetch200(body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    type: "basic",
    redirected: false,
    url: "https://registry.npmjs.org/test-pkg/1.0.0",
    headers: { get: (_: string) => null },
    body: null, // no stream — falls through to json()
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response);
}

/** Build a fetch mock that returns a non-2xx status. */
function makeFetchError(status: number) {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    type: "basic",
    redirected: false,
    url: `https://registry.npmjs.org/test-pkg/1.0.0`,
    headers: { get: (_: string) => null },
    body: null,
    json: vi.fn().mockResolvedValue({}),
  } as unknown as Response);
}

// ---------------------------------------------------------------------------
// fetchNpmIntegrity — happy path
// ---------------------------------------------------------------------------

describe("fetchNpmIntegrity — happy path", () => {
  it("returns {npmVersion, integrity} from a successful response", async () => {
    const sri = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const fetchImpl = makeFetch200(makeNpmVersionResponse(sri));

    const result = await fetchNpmIntegrity("left-pad", "1.3.0", { fetchImpl: fetchImpl as unknown as typeof fetch });

    expect(result).toEqual({ npmVersion: "1.3.0", integrity: sri });
  });

  it("URL-encodes an unscoped package name and version", async () => {
    const sri = "sha512-BBB==";
    const fetchImpl = makeFetch200(makeNpmVersionResponse(sri));

    await fetchNpmIntegrity("left-pad", "1.3.0", { fetchImpl: fetchImpl as unknown as typeof fetch });

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toBe("https://registry.npmjs.org/left-pad/1.3.0");
  });

  it("URL-encodes a scoped package name (@ and / → %40 and %2F)", async () => {
    const sri = "sha512-CCC==";
    const fetchImpl = makeFetch200(makeNpmVersionResponse(sri));

    await fetchNpmIntegrity("@scope/name", "2.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    // encodeURIComponent("@scope/name") = "%40scope%2Fname"
    expect(calledUrl).toBe("https://registry.npmjs.org/%40scope%2Fname/2.0.0");
  });

  it("URL-encodes the version segment", async () => {
    const sri = "sha512-DDD==";
    const fetchImpl = makeFetch200(makeNpmVersionResponse(sri));

    await fetchNpmIntegrity("pkg", "1.0.0-beta.1", { fetchImpl: fetchImpl as unknown as typeof fetch });

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl).toBe("https://registry.npmjs.org/pkg/1.0.0-beta.1");
  });

  it("host is always registry.npmjs.org (hardcoded, not caller-overridable)", async () => {
    const sri = "sha512-EEE==";
    const fetchImpl = makeFetch200(makeNpmVersionResponse(sri));

    await fetchNpmIntegrity("some-pkg", "3.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });

    const calledUrl = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
    expect(calledUrl.startsWith("https://registry.npmjs.org/")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// fetchNpmIntegrity — FAIL-OPEN: all failure modes resolve undefined, never throw
// ---------------------------------------------------------------------------

describe("fetchNpmIntegrity — FAIL-OPEN (all failures → undefined, never throw)", () => {
  it("returns undefined on 404", async () => {
    const fetchImpl = makeFetchError(404);
    const result = await fetchNpmIntegrity("no-such-pkg", "9.9.9", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined on 5xx", async () => {
    const fetchImpl = makeFetchError(500);
    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined when fetch throws a network error", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined on abort/timeout", async () => {
    const fetchImpl = vi.fn().mockImplementation(() => {
      const err = new DOMException("The operation was aborted.", "AbortError");
      return Promise.reject(err);
    });
    const result = await fetchNpmIntegrity("pkg", "1.0.0", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      timeoutMs: 1,
    });
    expect(result).toBeUndefined();
  });

  it("returns undefined on malformed JSON", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: { get: (_: string) => null },
      body: null,
      json: vi.fn().mockRejectedValue(new SyntaxError("Unexpected token")),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined when dist.integrity is missing", async () => {
    const bodyWithoutIntegrity = { name: "pkg", version: "1.0.0", dist: { shasum: "abc" } };
    const fetchImpl = makeFetch200(bodyWithoutIntegrity);
    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined when dist.integrity is not a string", async () => {
    const body = { name: "pkg", version: "1.0.0", dist: { integrity: 42 } };
    const fetchImpl = makeFetch200(body);
    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined when body is over the cap (Content-Length header)", async () => {
    const overCapBytes = (2 * 1024 * 1024 + 1).toString();
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: { get: (h: string) => (h === "content-length" ? overCapBytes : null) },
      body: null,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("never throws — all errors resolve to undefined", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    // Must not throw
    await expect(
      fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch })
    ).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// fetchNpmIntegrity — redirect handling
// ---------------------------------------------------------------------------

describe("fetchNpmIntegrity — redirect handling", () => {
  it("returns undefined on cross-host redirect (off-host 3xx)", async () => {
    // Simulate a response that looks like a redirect to a different host
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 301,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: {
        get: (h: string) => (h === "location" ? "https://evil.example.com/pkg" : null),
      },
      body: null,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("returns undefined on non-https redirect", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 302,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: {
        get: (h: string) => (h === "location" ? "http://registry.npmjs.org/pkg/1.0.0" : null),
      },
      body: null,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });

  it("does NOT follow redirects — a same-host 302 resolves to undefined, and fetch is called with redirect:'manual'", async () => {
    // redirect:"manual" means we never re-fetch a Location; even a same-host
    // 302 is refused (fail-open). This proves the guard is real, not dead code.
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 302,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: {
        get: (h: string) =>
          h === "location" ? "https://registry.npmjs.org/pkg/1.0.0" : null,
      },
      body: null,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ redirect: "manual" })
    );
  });

  it("treats an opaqueredirect (status 0) as a refused redirect → undefined", async () => {
    const fetchImpl = vi.fn().mockResolvedValue({
      ok: false,
      status: 0,
      type: "opaqueredirect",
      redirected: false,
      url: "https://registry.npmjs.org/pkg/1.0.0",
      headers: { get: (_: string) => null },
      body: null,
      json: vi.fn().mockResolvedValue({}),
    } as unknown as Response);

    const result = await fetchNpmIntegrity("pkg", "1.0.0", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(result).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// fetchNpmIntegrity — body cap (streaming path)
// ---------------------------------------------------------------------------

describe("fetchNpmIntegrity — body cap (streaming path)", () => {
  /** Build a 200 fetch whose body is a ReadableStream of the given chunks. */
  function makeStreamFetch(chunks: Uint8Array[], contentLength: string | null) {
    let i = 0;
    return vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      type: "basic",
      redirected: false,
      url: "https://registry.npmjs.org/test-pkg/1.0.0",
      headers: {
        get: (h: string) =>
          h.toLowerCase() === "content-length" ? contentLength : null,
      },
      body: {
        getReader: () => ({
          read: async () =>
            i < chunks.length
              ? { done: false, value: chunks[i++] }
              : { done: true, value: undefined },
          cancel: async () => {},
        }),
      },
    } as unknown as Response);
  }

  it("returns undefined when the streamed body exceeds the 2MB cap (Content-Length absent)", async () => {
    // One chunk just over the 2 MB cap; the streaming reader must bail before decode.
    const bigChunk = new Uint8Array(2 * 1024 * 1024 + 1);
    const fetchImpl = makeStreamFetch([bigChunk], null);
    const result = await fetchNpmIntegrity("test-pkg", "1.0.0", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(result).toBeUndefined();
  });

  it("reads a normal streamed body under the cap and returns the integrity", async () => {
    const sri = "sha512-STREAMOK==";
    const chunk = new TextEncoder().encode(
      JSON.stringify(makeNpmVersionResponse(sri))
    );
    const fetchImpl = makeStreamFetch([chunk], null);
    const result = await fetchNpmIntegrity("test-pkg", "1.0.0", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(result).toEqual({ npmVersion: "1.0.0", integrity: sri });
  });
});

// ---------------------------------------------------------------------------
// compareIntegrity
// ---------------------------------------------------------------------------

describe("compareIntegrity", () => {
  const SHA512_A = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
  const SHA512_B = "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";
  const SHA256_A = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
  const SHA1_A   = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const SHA1_B   = "sha1-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

  it("returns 'equal' for identical sha512 digests", () => {
    expect(compareIntegrity(SHA512_A, SHA512_A)).toBe("equal");
  });

  it("returns 'differ' for different sha512 digests", () => {
    expect(compareIntegrity(SHA512_A, SHA512_B)).toBe("differ");
  });

  it("returns 'equal' when multi-hash locked has matching sha512", () => {
    // locked: "sha512-X sha1-Y"; fresh: "sha512-X" — strongest common = sha512, same digest
    const locked = `${SHA512_A} ${SHA1_B}`;
    const fresh = SHA512_A;
    expect(compareIntegrity(locked, fresh)).toBe("equal");
  });

  it("returns 'differ' when multi-hash locked has differing sha512", () => {
    const locked = `${SHA512_A} ${SHA1_A}`;
    const fresh = SHA512_B;
    expect(compareIntegrity(locked, fresh)).toBe("differ");
  });

  it("returns 'format-only' when locked and fresh share NO common algorithm", () => {
    // locked: sha1 only; fresh: sha512 only → no common algo
    expect(compareIntegrity(SHA1_A, SHA512_A)).toBe("format-only");
  });

  it("prefers sha512 over sha256 when both present", () => {
    // locked has sha512-A + sha256-A; fresh has sha512-B + sha256-A
    // sha512 is picked (strongest), digests differ → "differ"
    const locked = `${SHA512_A} ${SHA256_A}`;
    const fresh = `${SHA512_B} ${SHA256_A}`;
    expect(compareIntegrity(locked, fresh)).toBe("differ");
  });

  it("falls back to sha256 when sha512 absent from both", () => {
    // Both have sha256-A → equal
    expect(compareIntegrity(SHA256_A, SHA256_A)).toBe("equal");
  });

  it("is robust to extra whitespace and ordering", () => {
    const locked = `  ${SHA1_A}  ${SHA512_A}  `;
    const fresh = `${SHA512_A}`;
    expect(compareIntegrity(locked, fresh)).toBe("equal");
  });

  it("returns 'equal' for identical sha1 when sha1 is the only common algorithm", () => {
    expect(compareIntegrity(SHA1_A, SHA1_A)).toBe("equal");
  });

  it("returns 'differ' for different sha256 digests", () => {
    const SHA256_B = "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==";
    expect(compareIntegrity(SHA256_A, SHA256_B)).toBe("differ");
  });
});
