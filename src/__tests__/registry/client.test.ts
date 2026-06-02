/**
 * Tests for src/registry/client.ts
 *
 * Focus: getServer must percent-encode the caller-supplied `version` as a path
 * segment so a value like "../latest" or "latest?inject=1" (from an unvalidated
 * lockfile/stack `version` string) cannot manipulate the request path or smuggle
 * in a query string. Also asserts no stray ?version= query param is produced.
 * (security: version path-injection)
 */

import { describe, it, expect, vi } from "vitest";
import { RegistryClient } from "../../registry/client.js";

const NAME = "io.github.org/server-name";

function serverEntry(version: string) {
  return {
    server: {
      name: NAME,
      version,
      packages: [],
    },
  };
}

/** Build a client whose fetch records the URL and returns a fixed entry. */
function makeClient(version: string) {
  const calls: string[] = [];
  const fetchImpl = vi.fn(async (url: string) => {
    calls.push(url);
    return {
      ok: true,
      status: 200,
      type: "basic",
      headers: { get: () => null },
      json: async () => serverEntry(version),
    } as unknown as Response;
  });
  const client = new RegistryClient({
    baseUrl: "https://registry.example.com",
    fetchImpl: fetchImpl as unknown as typeof fetch,
  });
  return { client, calls };
}

describe("RegistryClient.getServer — version path-segment encoding", () => {
  it("defaults to the 'latest' segment with no query string", async () => {
    const { client, calls } = makeClient("1.0.0");
    await client.getServer(NAME);
    expect(calls[0]).toBe(
      "https://registry.example.com/v0.1/servers/io.github.org%2Fserver-name/versions/latest"
    );
    // No redundant/dead ?version= query param.
    expect(calls[0]).not.toContain("?");
  });

  it("percent-encodes a normal version into the path segment", async () => {
    const { client, calls } = makeClient("1.2.3");
    await client.getServer(NAME, "1.2.3");
    expect(calls[0]).toContain("/versions/1.2.3");
    expect(calls[0]).not.toContain("?");
  });

  it("encodes a query-injecting version so no query string is produced", async () => {
    const { client, calls } = makeClient("latest");
    await client.getServer(NAME, "latest?inject=1");
    // The "?" and "=" must be percent-encoded inside the path segment.
    expect(calls[0]).not.toContain("?");
    expect(calls[0]).toContain("/versions/latest%3Finject%3D1");
  });

  it("encodes a path-traversal version so it cannot escape the segment", async () => {
    const { client, calls } = makeClient("latest");
    await client.getServer(NAME, "../latest");
    // The slash must be encoded — the value stays a single segment.
    expect(calls[0]).not.toContain("/versions/../latest");
    expect(calls[0]).toContain("/versions/..%2Flatest");
  });
});
