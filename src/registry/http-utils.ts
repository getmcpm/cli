/**
 * Shared HTTP utilities for the registry clients.
 *
 * The capped-body reader lives here so BOTH the read client (client.ts) and the
 * publish client (publish-client.ts) enforce the same response-size cap. A
 * hostile or misconfigured `--registry` can return a small compressed payload
 * that decompresses to GBs (decompression bomb → OOM), so we refuse bodies
 * larger than MAX_RESPONSE_BYTES. (security #21)
 */

import { NetworkError, ValidationError } from "./errors.js";

/**
 * Cap on response body size before parsing. A hostile (or 30x-redirected) host
 * can return a small compressed payload that decompresses to GBs (decompression
 * bomb → OOM). We refuse bodies larger than this. (security #21)
 */
export const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

/**
 * Read and JSON-parse a response body with a hard byte cap, so a hostile host
 * cannot OOM us with an unbounded (or decompression-bomb) body. It:
 *   1. Rejects early if a declared Content-Length exceeds the cap.
 *   2. If a readable stream is present, reads it chunk-by-chunk and aborts
 *      once MAX_RESPONSE_BYTES is exceeded — before fully decompressing.
 *   3. Otherwise falls back to response.json() (e.g. non-stream Responses).
 * (security #21)
 */
export async function readCappedBody(
  url: string,
  response: Response
): Promise<unknown> {
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined) {
    const len = Number(declared);
    if (Number.isFinite(len) && len > MAX_RESPONSE_BYTES) {
      throw new ValidationError(
        `Registry response from ${url} too large (${len} bytes > ${MAX_RESPONSE_BYTES} cap).`
      );
    }
  }

  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const text = await readCappedStream(url, body);
    try {
      return JSON.parse(text);
    } catch (err) {
      throw new ValidationError(
        `Failed to parse JSON response from ${url}`,
        err
      );
    }
  }

  // No readable stream (e.g. injected mock / non-stream Response). The
  // Content-Length guard above is our cap here.
  try {
    return await response.json();
  } catch (err) {
    throw new ValidationError(
      `Failed to parse JSON response from ${url}`,
      err
    );
  }
}

/**
 * Read a ReadableStream as UTF-8 text, throwing once the running total exceeds
 * MAX_RESPONSE_BYTES — without buffering the whole (possibly bomb) body first.
 */
async function readCappedStream(
  url: string,
  body: ReadableStream<Uint8Array>
): Promise<string> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          throw new ValidationError(
            `Registry response from ${url} exceeded ${MAX_RESPONSE_BYTES} byte cap.`
          );
        }
        chunks.push(value);
      }
    }
  } finally {
    // Best-effort: release the stream even on the cap-exceeded path.
    await reader.cancel().catch(() => {});
  }
  return new TextDecoder().decode(concatChunks(chunks, total));
}

function concatChunks(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

/**
 * FAIL-OPEN capped-body reader shared by the npm tripwires (npm-integrity.ts /
 * npm-provenance.ts). Unlike readCappedBody (which THROWS a ValidationError on
 * an over-cap / unparseable body), this returns `undefined` on ANY failure —
 * over-cap Content-Length, over-cap stream, unreadable body, or non-JSON — so
 * a tripwire can fail OPEN and never crash the command it guards.
 *
 * @param response - the fetch Response to read
 * @param capBytes - hard byte cap for the body
 */
export async function readCappedJsonOrUndefined(
  response: Response,
  capBytes: number
): Promise<unknown> {
  // Guard on declared Content-Length first (fast path for huge responses).
  const declared = response.headers?.get?.("content-length");
  if (declared !== null && declared !== undefined) {
    const len = Number(declared);
    if (Number.isFinite(len) && len > capBytes) return undefined;
  }

  const body = response.body;
  if (body && typeof body.getReader === "function") {
    const text = await readCappedStreamOrUndefined(body, capBytes);
    if (text === undefined) return undefined;
    try {
      return JSON.parse(text);
    } catch {
      return undefined;
    }
  }

  // No readable stream (e.g. injected mock). The Content-Length guard above
  // is our cap in this path.
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

async function readCappedStreamOrUndefined(
  body: ReadableStream<Uint8Array>,
  capBytes: number
): Promise<string | undefined> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > capBytes) return undefined;
        chunks.push(value);
      }
    }
  } catch {
    return undefined;
  } finally {
    await reader.cancel().catch(() => {});
  }
  return new TextDecoder().decode(concatChunks(chunks, total));
}

// ---------------------------------------------------------------------------
// Deadline-covered body read + one bounded retry (maintainer backlog #90)
// ---------------------------------------------------------------------------

/**
 * `readCappedBody`, but any failure that is NOT a ValidationError surfaces as a
 * NetworkError.
 *
 * Every registry fetch runs under an AbortController deadline. Once that deadline
 * also covers the body read (it did not — see the callers), a stalled body aborts
 * mid-stream and `reader.read()` rejects with an AbortError, which is a network
 * condition and should be classified and retried as one. A ValidationError
 * (over-cap or unparseable body) is a fact about the payload, not the link, and
 * is rethrown untouched so it is never retried.
 */
export async function readCappedBodyWithinDeadline(
  url: string,
  response: Response
): Promise<unknown> {
  try {
    return await readCappedBody(url, response);
  } catch (err) {
    if (err instanceof ValidationError) throw err;
    throw new NetworkError(
      `Response body read failed: ${url}`,
      err instanceof Error ? err : new Error(String(err))
    );
  }
}

/**
 * Delay before the single retry. Deliberately short: this covers a transient
 * blip or a request that lost a race with tail latency, NOT an outage. Measured
 * registry tail latency (2026-09-17, 17 samples) reached 10-24 s on 4 of them,
 * which one retry of a 10 s-deadline GET covers and a longer backoff would not.
 */
export const RETRY_DELAY_MS = 400;

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Run `attempt`; if it throws something `shouldRetry` accepts, run it exactly
 * ONCE more after a short delay and return that outcome.
 *
 * One retry, not N: mcpm's registry reads sit in front of a human or an agent
 * waiting on a command, so an unbounded backoff ladder trades a visible failure
 * for an invisible hang. `attempt` takes its own AbortController per call, so
 * the retry gets a fresh, full deadline rather than the remains of the first.
 */
export async function withOneRetry<T>(
  attempt: () => Promise<T>,
  shouldRetry: (err: unknown) => boolean,
  sleep: (ms: number) => Promise<void> = defaultSleep
): Promise<T> {
  try {
    return await attempt();
  } catch (err) {
    if (!shouldRetry(err)) throw err;
    await sleep(RETRY_DELAY_MS);
    return await attempt();
  }
}

/**
 * The outcome of a fail-open fetch. `status === undefined` means BOTH attempts
 * threw — a network failure, never an answer from the server.
 */
export interface FailOpenFetchResult {
  readonly status: number | undefined;
  readonly type: string | undefined;
  readonly ok: boolean;
  /** Parsed JSON body, or undefined for a non-ok, unreadable or over-cap body. */
  readonly json: unknown;
}

/**
 * Fetch + capped JSON body read under ONE deadline, retried once on a thrown
 * network failure, never throwing. Shared by the two npm tripwires
 * (npm-integrity, npm-provenance), which are contracted to fail open.
 *
 * Both halves of that contract matter here. The deadline covers the body read,
 * so a stalled body can no longer hang a command forever (it used to be cleared
 * in the fetch's own `finally`). And the single retry exists because failing
 * open is not free on this path: `up --frozen` / `mcpm verify` BLOCK on
 * "could-not-verify", so a one-off blip fetching a manifest fails a CI install
 * over a network hiccup rather than over any fact about the package.
 *
 * The body is only read when the response is ok, so a 404 — the ONLY path to
 * "unsigned" in npm-provenance — still resolves without touching the body.
 */
export async function fetchJsonFailOpenWithOneRetry(
  url: string,
  init: Omit<RequestInit, "signal">,
  opts: {
    timeoutMs: number;
    capBytes: number;
    fetchImpl: typeof fetch;
    sleep?: (ms: number) => Promise<void>;
  }
): Promise<FailOpenFetchResult> {
  const sleep = opts.sleep ?? defaultSleep;
  const NETWORK_FAILURE: FailOpenFetchResult = {
    status: undefined,
    type: undefined,
    ok: false,
    json: undefined,
  };

  const once = async (): Promise<FailOpenFetchResult> => {
    // A fresh controller per attempt, so the retry gets a full deadline rather
    // than the remains of the first one.
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      let response: Response;
      try {
        response = await opts.fetchImpl(url, { ...init, signal: controller.signal });
      } catch {
        return NETWORK_FAILURE;
      }
      if (!response.ok) {
        return { status: response.status, type: response.type, ok: false, json: undefined };
      }
      return {
        status: response.status,
        type: response.type,
        ok: true,
        json: await readCappedJsonOrUndefined(response, opts.capBytes),
      };
    } finally {
      clearTimeout(timerId);
    }
  };

  const first = await once();
  if (first.status !== undefined) return first;
  await sleep(RETRY_DELAY_MS);
  return once();
}
