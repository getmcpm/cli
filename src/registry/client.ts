/**
 * RegistryClient — typed HTTP client for the official MCP Registry API v0.1.
 *
 * Design decisions:
 * - fetchImpl is injectable for hermetic testing (no real network calls needed).
 * - All responses are validated through Zod schemas before being returned.
 * - Errors are mapped to the typed error hierarchy in errors.ts.
 * - Returned objects are always new (immutable) — never mutate cached values.
 * - AbortController is used per-request so timeout applies per call.
 */

import {
  SearchResponseSchema,
  ServerEntrySchema,
  ServerVersionsResponseSchema,
} from "./schemas.js";
import type { SearchResult, ServerEntry, ServerVersion } from "./types.js";
import {
  NetworkError,
  NotFoundError,
  RegistryError,
  ValidationError,
} from "./errors.js";
import { isPrivateHost } from "./publish-client.js";

const DEFAULT_BASE_URL = "https://registry.modelcontextprotocol.io";
const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Cap on response body size before parsing. A hostile (or 30x-redirected) host
 * can return a small compressed payload that decompresses to GBs (decompression
 * bomb → OOM). We refuse bodies larger than this. (security #21)
 */
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

/**
 * Validate a registry base URL before any request is made. `baseUrl` is fully
 * caller-overridable, so an attacker-chosen value must not let us talk to an
 * internal address (SSRF). Requires https and rejects loopback/private hosts —
 * mirrors validateRegistryUrl in publish-client.ts. (security #21)
 */
function validateBaseUrl(baseUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new RegistryError(`Invalid registry base URL: "${baseUrl}"`, 0);
  }
  if (parsed.protocol !== "https:") {
    throw new RegistryError(
      `Registry base URL must use https (got "${baseUrl}").`,
      0
    );
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new RegistryError(
      "Registry base URL must not contain embedded credentials.",
      0
    );
  }
  if (isPrivateHost(parsed.hostname)) {
    throw new RegistryError(
      `Refusing to use non-public registry host "${parsed.hostname}".`,
      0
    );
  }
}

export interface RegistryClientOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeout?: number;
}

export interface SearchOptions {
  limit?: number;
  version?: string;
  cursor?: string;
}

function stripTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

export class RegistryClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeout: number;

  constructor(options: RegistryClientOptions = {}) {
    const baseUrl = stripTrailingSlash(options.baseUrl ?? DEFAULT_BASE_URL);
    // Validate the (possibly caller-supplied) base URL up front: https-only,
    // no embedded creds, no loopback/private hosts (SSRF). (security #21)
    validateBaseUrl(baseUrl);
    this.baseUrl = baseUrl;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  }

  /**
   * Search for servers by name substring.
   * The official API only matches on server name, not description.
   */
  async searchServers(
    query: string,
    options: SearchOptions = {}
  ): Promise<SearchResult> {
    const params = new URLSearchParams();
    params.set("search", query);
    params.set("version", options.version ?? "latest");
    if (options.limit !== undefined) {
      params.set("limit", String(options.limit));
    }
    if (options.cursor !== undefined) {
      params.set("cursor", options.cursor);
    }

    const url = `${this.baseUrl}/v0.1/servers?${params.toString()}`;
    const raw = await this.get(url);
    const parsed = SearchResponseSchema.safeParse(raw);

    if (!parsed.success) {
      throw new ValidationError(
        `Invalid search response: ${parsed.error.message}`,
        parsed.error
      );
    }

    // Return a new object (immutable pattern — never return cached reference)
    return { ...parsed.data };
  }

  /**
   * Fetch a single server by its namespaced name (e.g. "io.github.org/server-name").
   * The slash in the name must be percent-encoded when used as a path segment.
   */
  async getServer(name: string, version?: string): Promise<ServerEntry> {
    const encodedName = encodeURIComponent(name);
    const params = new URLSearchParams();
    if (version !== undefined) {
      params.set("version", version);
    }
    const versionSegment = version ?? "latest";
    const url = `${this.baseUrl}/v0.1/servers/${encodedName}/versions/${versionSegment}`;

    const raw = await this.get(url, name);
    const parsed = ServerEntrySchema.safeParse(raw);

    if (!parsed.success) {
      throw new ValidationError(
        `Invalid server response for "${name}": ${parsed.error.message}`,
        parsed.error
      );
    }

    return { ...parsed.data };
  }

  /**
   * Fetch all published versions for a given server name.
   */
  async getServerVersions(name: string): Promise<ServerVersion[]> {
    const encodedName = encodeURIComponent(name);
    const url = `${this.baseUrl}/v0.1/servers/${encodedName}/versions`;

    const raw = await this.get(url, name);
    const parsed = ServerVersionsResponseSchema.safeParse(raw);

    if (!parsed.success) {
      throw new ValidationError(
        `Invalid versions response for "${name}": ${parsed.error.message}`,
        parsed.error
      );
    }

    // Return a new array (immutable)
    return [...parsed.data.versions];
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Perform a GET request with timeout and unified error mapping.
   * @param serverName — optionally provided for 404 error messages
   */
  private async get(url: string, serverName?: string): Promise<unknown> {
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), this.timeout);

    let response: Response;
    try {
      // redirect:"manual" — never silently follow a 3xx to an attacker-chosen
      // (possibly internal) host. A redirect surfaces as an opaqueredirect /
      // status-0 response and is rejected below. (security #21)
      response = await this.fetchImpl(url, {
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (err) {
      throw new NetworkError(
        `Network request failed: ${url}`,
        err instanceof Error ? err : new Error(String(err))
      );
    } finally {
      clearTimeout(timerId);
    }

    // A 3xx surfaces as an opaqueredirect (status 0) under redirect:"manual",
    // or as a 3xx status if the runtime exposes it. Treat both as an error —
    // we do not follow cross-origin redirects. (security #21)
    if (
      response.type === "opaqueredirect" ||
      (response.status >= 300 && response.status < 400)
    ) {
      throw new RegistryError(
        `Registry returned a redirect (${response.status}) for ${url}; refusing to follow it.`,
        response.status
      );
    }

    if (!response.ok) {
      if (response.status === 404) {
        throw new NotFoundError(serverName ?? url);
      }
      throw new RegistryError(
        `Registry API returned ${response.status} for ${url}`,
        response.status
      );
    }

    return this.readCappedBody(url, response);
  }

  /**
   * Read and JSON-parse a response body with a hard byte cap, so a hostile host
   * cannot OOM us with an unbounded (or decompression-bomb) body. It:
   *   1. Rejects early if a declared Content-Length exceeds the cap.
   *   2. If a readable stream is present, reads it chunk-by-chunk and aborts
   *      once MAX_RESPONSE_BYTES is exceeded — before fully decompressing.
   *   3. Otherwise falls back to response.json() (e.g. non-stream Responses).
   * (security #21)
   */
  private async readCappedBody(
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
