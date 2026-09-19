/**
 * #90 — the request deadline must cover the BODY read, and one bounded retry.
 *
 * (a) `clearTimeout(timerId)` ran in the FETCH's own `finally`, so a response
 *     whose headers arrived promptly and whose body then stalled had no timeout
 *     left to fire: the command hung forever. Same shape in publish-client,
 *     npm-integrity and npm-provenance.
 *
 * (b) Nothing retried anywhere. Measured registry tail latency (2026-09-17, 17
 *     samples) reached 10-24 s on 4 of them, against a 10 s client deadline; the
 *     v0.40.1 `registry` publish job failed when `POST /v0.1/publish` exceeded
 *     its 15 s deadline while a plain GET against the same host took 35 s.
 *
 * Driven with an injected fetch that produces a REAL ReadableStream honouring
 * the caller's AbortSignal — a resolved-promise stub would never exercise the
 * abort path that is the whole point of (a).
 */

import { describe, it, expect, vi } from "vitest";
import { RegistryClient } from "../../registry/client.js";
import { NetworkError } from "../../registry/errors.js";

/**
 * A Response whose body stream never yields and rejects when the signal aborts —
 * i.e. a server that answered its headers and then went quiet.
 */
function stalledBodyResponse(signal: AbortSignal): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      signal.addEventListener("abort", () => controller.error(new Error("aborted")), { once: true });
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "application/json" } });
}

function jsonResponse(payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

const SERVER_PAYLOAD = {
  server: { name: "io.github.test/srv", version: "1.0.0" },
};

describe("RegistryClient — the deadline covers the body read (#90)", () => {
  it("rejects a stalled body instead of hanging forever", async () => {
    const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) =>
      stalledBodyResponse(init!.signal as AbortSignal)
    ) as unknown as typeof fetch;

    const client = new RegistryClient({
      baseUrl: "https://registry.example.com",
      fetchImpl,
      timeout: 40,
    });

    // Before the fix this promise never settled; the test would time out rather
    // than fail, which is itself the symptom.
    await expect(client.getServer("io.github.test/srv")).rejects.toThrow();
    // Both attempts (original + the one retry) stalled and aborted.
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  }, 10_000);

  it("classifies a deadline that fires mid-body as a NetworkError, not an unknown", async () => {
    const fetchImpl = vi.fn(async (_url: string, init?: RequestInit) =>
      stalledBodyResponse(init!.signal as AbortSignal)
    ) as unknown as typeof fetch;

    const client = new RegistryClient({
      baseUrl: "https://registry.example.com",
      fetchImpl,
      timeout: 40,
    });

    await expect(client.getServer("io.github.test/srv")).rejects.toBeInstanceOf(NetworkError);
  }, 10_000);
});

describe("RegistryClient — one bounded retry (#90)", () => {
  it("retries a NetworkError exactly once and succeeds on the second attempt", async () => {
    let calls = 0;
    const fetchImpl = vi.fn(async () => {
      calls += 1;
      if (calls === 1) throw new TypeError("fetch failed");
      return jsonResponse(SERVER_PAYLOAD);
    }) as unknown as typeof fetch;

    const client = new RegistryClient({ baseUrl: "https://registry.example.com", fetchImpl });
    const entry = await client.getServer("io.github.test/srv");

    expect(entry.server.name).toBe("io.github.test/srv");
    expect(calls).toBe(2);
  });

  it("gives up after the single retry — it does not loop", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof fetch;

    const client = new RegistryClient({ baseUrl: "https://registry.example.com", fetchImpl });
    await expect(client.getServer("io.github.test/srv")).rejects.toBeInstanceOf(NetworkError);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["a 404", 404],
    ["a 500", 500],
  ])("does NOT retry %s — a deterministic answer is not worth asking twice", async (_l, status) => {
    const fetchImpl = vi.fn(async () => new Response("{}", { status })) as unknown as typeof fetch;

    const client = new RegistryClient({ baseUrl: "https://registry.example.com", fetchImpl });
    await expect(client.getServer("io.github.test/srv")).rejects.toThrow();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does NOT retry an unparseable body — that is a fact about the payload", async () => {
    const fetchImpl = vi.fn(
      async () => new Response("not json at all", { status: 200 })
    ) as unknown as typeof fetch;

    const client = new RegistryClient({ baseUrl: "https://registry.example.com", fetchImpl });
    await expect(client.getServer("io.github.test/srv")).rejects.toThrow();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});
