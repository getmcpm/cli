/**
 * Shared HTTP utilities for the registry clients.
 *
 * The capped-body reader lives here so BOTH the read client (client.ts) and the
 * publish client (publish-client.ts) enforce the same response-size cap. A
 * hostile or misconfigured `--registry` can return a small compressed payload
 * that decompresses to GBs (decompression bomb → OOM), so we refuse bodies
 * larger than MAX_RESPONSE_BYTES. (security #21)
 */

import { ValidationError } from "./errors.js";

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
