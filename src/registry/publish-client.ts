/**
 * Registry publish client — auth token exchange + the publish submit endpoint.
 * Shares timeout/error infrastructure with RegistryClient.
 *
 * Endpoint paths and required auth were verified live against
 * registry.modelcontextprotocol.io on 2026-09-14 (see #216): `/v0.1/servers` is GET-only (POST 404s); publishing is `POST /v0.1/publish`,
 * authenticated with a registry JWT obtained by exchange — never the raw GitHub
 * token/PAT — from `POST /v0.1/auth/github-at` ({github_token}) or, inside GitHub
 * Actions, `POST /v0.1/auth/github-oidc` ({oidc_token}).
 */

import type { ServerJson } from "../commands/publish/manifest.js";
import type { SubmitResult } from "../commands/publish/submit.js";
import { NetworkError, RegistryError } from "./errors.js";
import { readCappedBody, readCappedBodyWithinDeadline, withOneRetry } from "./http-utils.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";

const DEFAULT_TIMEOUT_MS = 15_000;

export interface RegistryTokenResponse {
  registryToken: string;
  expiresAt: number;
}

/**
 * Validate a publish registry URL before the user's auth token is attached.
 * The token (a GitHub PAT) must never leak to an attacker-chosen host via a
 * typo'd/malicious `--registry`, an http downgrade, or an internal address
 * (SSRF). Requires https and rejects loopback/private hosts. (security #17)
 */
export function validateRegistryUrl(registryUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(registryUrl);
  } catch {
    throw new RegistryError(`Invalid registry URL: "${registryUrl}"`, 0);
  }
  if (parsed.protocol !== "https:") {
    throw new RegistryError(
      `Refusing to send auth token over ${parsed.protocol || "an insecure protocol"} — ` +
        `registry must use https (got "${registryUrl}").`,
      0
    );
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw new RegistryError("Registry URL must not contain embedded credentials.", 0);
  }
  if (isPrivateHost(parsed.hostname)) {
    throw new RegistryError(
      `Refusing to send auth token to non-public host "${parsed.hostname}".`,
      0
    );
  }
}

export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h === "::1" || h === "::" || h === "0.0.0.0" || h === "") return true;
  // IPv4-mapped IPv6 (Node normalizes [::ffff:127.0.0.1] → ::ffff:7f00:1).
  // Decode the embedded IPv4 and re-check, or treat unknown forms as private.
  const mapped = h.match(/^::ffff:(.+)$/);
  if (mapped) {
    const inner = mapped[1];
    if (inner.includes(".")) return isPrivateHost(inner);
    const hx = inner.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hx) {
      const n = ((parseInt(hx[1], 16) << 16) | parseInt(hx[2], 16)) >>> 0;
      return isPrivateHost(`${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
    }
    return true;
  }
  const m = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}$/);
  if (m) {
    const a = Number(m[1]);
    const b = Number(m[2]);
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10 (RFC 6598)
  }
  // IPv6 link-local (fe80::/10) and unique-local (fc00::/7) are matched by the
  // numeric value of the first 16-bit hextet, NOT a string prefix. A loose
  // `startsWith("fe80")` misses the rest of fe80::/10 — e.g. feb0::1, fea0::1,
  // febf::1 are all link-local but don't begin literally with "fe80", so they
  // would bypass the SSRF guard before the Bearer token is attached.
  const firstHextet = parseFirstHextet(h);
  if (firstHextet !== null) {
    if (firstHextet >= 0xfe80 && firstHextet <= 0xfebf) return true; // link-local fe80::/10
    if (firstHextet >= 0xfc00 && firstHextet <= 0xfdff) return true; // unique-local fc00::/7
    // 6to4 (2002::/16) embeds an arbitrary IPv4 in the next 32 bits, so it can be
    // used to reach a private/internal v4 host (e.g. 2002:7f00:1:: → 127.0.0.1).
    // Block the whole 2002::/16 block before the Bearer token is attached.
    if (firstHextet === 0x2002) return true;
  }
  return false;
}

/**
 * Parse the first 16-bit group of an IPv6 address (already bracket-stripped and
 * lowercased). Returns null if the host isn't an IPv6 literal we recognize.
 * "fe80::1" → 0xfe80, "::1" → 0 (leading "::"). Anything non-IPv6 → null.
 */
function parseFirstHextet(h: string): number | null {
  // Must look like an IPv6 address: contains ":" and only hex digits / colons.
  if (!h.includes(":") || !/^[0-9a-f:]+$/.test(h)) return null;
  // "::..." means the first hextet is zero (the "::" elides leading zero groups).
  if (h.startsWith("::")) return 0;
  const first = h.split(":", 1)[0];
  if (first === "" || first.length > 4) return null;
  const n = parseInt(first, 16);
  return Number.isNaN(n) ? null : n;
}

/**
 * Shared POST helper: validates the registry URL, refuses to follow redirects
 * (so a token/body never reaches a 3xx target), and enforces the response-size
 * cap (security #21) before returning the parsed JSON body on success.
 */
async function postJson(
  url: string,
  body: unknown,
  headers: Record<string, string>
): Promise<unknown> {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  // #90: one outer try/finally so the deadline stays armed through the BODY read.
  // It used to be cleared in the fetch's own `finally`, leaving a stalled body
  // with no timeout left to fire.
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: "POST",
        // redirect:"manual" — a 3xx must NOT carry the Authorization token to the
        // redirect target. A redirect surfaces as a non-ok response and errors below.
        redirect: "manual",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      throw new NetworkError(
        `Network request failed: ${url}`,
        err instanceof Error ? err : new Error(String(err))
      );
    }

    if (response.type === "opaqueredirect" || response.status === 0) {
      throw new RegistryError(
        "Registry attempted a redirect (3xx); refusing to follow it with the auth token. Check the --registry URL.",
        0
      );
    }

    if (!response.ok) {
      throw new RegistryError(await describeError(url, response), response.status);
    }

    return await readCappedBodyWithinDeadline(url, response);
  } finally {
    clearTimeout(timerId);
  }
}

/**
 * The registry's error bodies are `application/problem+json`
 * ({title, status, detail, errors?: [{message, location, value}]}) — surface
 * `detail` and `errors[].message` so a 422 (missing/invalid fields) is
 * actually readable instead of just "Registry API returned 422".
 *
 * `detail`/`title`/`errors[].message`/`errors[].location` are REGISTRY-
 * CONTROLLED text that lands in a thrown Error's `.message`, which callers
 * print straight to the terminal (`console.error(chalk.red(err.message))` in
 * publish/index.ts) — so each piece is run through sanitizeForTerminal
 * (#216 review, MED 3) to strip ANSI/OSC/control-character injection before
 * it reaches stdout/stderr.
 *
 * `errors[].value` is deliberately NEVER interpolated (#216 review, LOW 8):
 * the registry echoes the request body back on a 422, so `value` can be
 * arbitrary submitted data (e.g. a `.mcpm-publish.yaml` field). Destructured
 * here only so a future edit that starts using it doesn't do so silently.
 */
async function describeError(url: string, response: Response): Promise<string> {
  const base = `Registry API returned ${response.status}`;
  try {
    const body = (await readCappedBody(url, response)) as {
      detail?: string;
      title?: string;
      errors?: Array<{ message?: string; location?: string; value?: unknown }>;
    };
    const parts = [base];
    if (body.detail) parts.push(sanitizeForTerminal(body.detail));
    else if (body.title) parts.push(sanitizeForTerminal(body.title));
    if (body.errors?.length) {
      parts.push(
        body.errors
          .map((e) =>
            [e.location, e.message]
              .filter(Boolean)
              .map((s) => sanitizeForTerminal(String(s)))
              .join(": ")
          )
          .join("; ")
      );
    }
    return parts.join(" — ");
  } catch {
    // Not a readable problem+json body (e.g. a plain-text 502 from a proxy, or
    // a test mock with no .json()/.body) — fall back to the bare status.
    return base;
  }
}

/**
 * Exchange a GitHub OAuth access token / PAT for a short-lived registry JWT.
 * POST /v0.1/auth/github-at — never sends the GitHub token anywhere else.
 */
export async function exchangeGitHubToken(
  registryUrl: string,
  githubToken: string
): Promise<RegistryTokenResponse> {
  validateRegistryUrl(registryUrl);
  // #90: one bounded retry on a NetworkError. Minting a short-lived JWT is
  // idempotent — a second exchange simply supersedes a first one that never
  // reached us — so unlike the publish POST below this is safe to re-send.
  const body = (await withOneRetry(
    () => postJson(`${registryUrl}/v0.1/auth/github-at`, { github_token: githubToken }, {}),
    (err) => err instanceof NetworkError
  )) as {
    registry_token: string;
    expires_at: number;
  };
  return { registryToken: body.registry_token, expiresAt: body.expires_at };
}

/**
 * Exchange a GitHub Actions OIDC token for a short-lived registry JWT.
 * POST /v0.1/auth/github-oidc — used by `mcpm publish --github-oidc` in CI,
 * where the OIDC token itself is minted by fetchActionsOidcToken.
 */
export async function exchangeGitHubOidcToken(
  registryUrl: string,
  oidcToken: string
): Promise<RegistryTokenResponse> {
  validateRegistryUrl(registryUrl);
  // #90: one bounded retry on a NetworkError — see exchangeGitHubToken.
  const body = (await withOneRetry(
    () => postJson(`${registryUrl}/v0.1/auth/github-oidc`, { oidc_token: oidcToken }, {}),
    (err) => err instanceof NetworkError
  )) as {
    registry_token: string;
    expires_at: number;
  };
  return { registryToken: body.registry_token, expiresAt: body.expires_at };
}

/**
 * OIDC audience for a given registry URL: scheme + lowercased host (host
 * INCLUDES the port, e.g. "example.com:8443"), matching the official
 * publisher's `audienceFromRegistryURL` (modelcontextprotocol/registry,
 * cmd/publisher/auth/github-oidc.go:182, `u.Host`) exactly — so a token
 * minted here validates against that registry's issuer check. #216 review,
 * MED 2: this previously used `parsed.hostname`, which DROPS the port —
 * `u.Host` in the Go reference keeps it — so a `--registry` on a non-default
 * port minted a token with the wrong audience (silently rejected by that
 * registry's issuer check, not a visible bug here).
 */
export function audienceFromRegistryUrl(registryUrl: string): string {
  const parsed = new URL(registryUrl);
  return `${parsed.protocol}//${parsed.host.toLowerCase()}`;
}

/**
 * Shared GET helper mirroring postJson's hardening — timeout, refuse to
 * follow redirects (so a token/Bearer header never reaches a 3xx target),
 * and the capped-body reader — for a non-registry endpoint (the GitHub
 * Actions token-request endpoint) that still carries a bearer credential.
 * (#216 review, LOW 7: fetchActionsOidcToken previously had none of this.)
 */
async function getJson(
  url: string,
  headers: Record<string, string>
): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  // #90: outer try/finally so the deadline also covers the body read.
  try {
    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        headers,
        signal: controller.signal,
      });
    } catch (err) {
      throw new NetworkError(
        `Network request failed: ${url}`,
        err instanceof Error ? err : new Error(String(err))
      );
    }

    if (response.type === "opaqueredirect" || response.status === 0) {
      throw new RegistryError(
        "GitHub Actions OIDC token endpoint attempted a redirect (3xx); refusing to follow it with the request token.",
        0
      );
    }

    if (!response.ok) {
      throw new RegistryError(`GitHub Actions OIDC token request returned ${response.status}`, response.status);
    }

    return { status: response.status, body: await readCappedBodyWithinDeadline(url, response) };
  } finally {
    clearTimeout(timerId);
  }
}

/**
 * Mints a GitHub Actions OIDC token for `audience` via the Actions runtime's
 * own token-request endpoint. Pure over an injected `env` (so it's testable
 * without real Actions env vars) + the global fetch.
 * Requires the job permission `id-token: write`; throws a clear error naming
 * it when ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN are absent (i.e. not running in
 * Actions, or the permission wasn't granted).
 */
export async function fetchActionsOidcToken(
  audience: string,
  env: Record<string, string | undefined>
): Promise<string> {
  const requestUrl = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestUrl || !requestToken) {
    throw new Error(
      [
        "mcpm publish --github-oidc: No GitHub Actions OIDC token request context.",
        "  Cause: ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set.",
        "  Fix:   Run this inside a GitHub Actions job with `permissions: { id-token: write }`.",
      ].join("\n")
    );
  }

  const url = `${requestUrl}&audience=${encodeURIComponent(audience)}`;
  // #90: one bounded retry on a NetworkError. A GET that mints an OIDC token is
  // idempotent from our side; GitHub's endpoint is the same one the whole job
  // depends on, and losing a release to a single blip here is not worth it.
  const { status, body: rawBody } = await withOneRetry(
    () =>
      getJson(url, {
        Authorization: `Bearer ${requestToken}`,
        Accept: "application/json",
      }),
    (err) => err instanceof NetworkError
  );
  const body = rawBody as { value?: string };
  if (!body.value) {
    throw new RegistryError("GitHub Actions OIDC token response had no value", status);
  }
  return body.value;
}

/**
 * Submit a ServerJSON body to the registry. `registryToken` must already be
 * the exchanged registry JWT (from exchangeGitHubToken/exchangeGitHubOidcToken)
 * — the raw GitHub token/PAT is never sent here.
 */
export async function submitToRegistry(
  serverJson: ServerJson,
  registryToken: string,
  registryUrl: string
): Promise<SubmitResult> {
  validateRegistryUrl(registryUrl);
  // #90: deliberately NOT retried here. The POST is not idempotent — the
  // registry answers a second submission of the same version with
  // `400 ... already exists`, so a blind re-send converts a timeout whose
  // request may well have LANDED into a hard, misleading failure. The recovery
  // is to ASK instead of re-sending, and it lives in handlePublishSubmit, which
  // can consult the version listing.
  const url = `${registryUrl}/v0.1/publish`;
  const body = (await postJson(url, serverJson, { Authorization: `Bearer ${registryToken}` })) as {
    url?: string;
  };
  // The live /v0.1/publish response body has no `url` field (confirmed
  // against registry.modelcontextprotocol.io, #216 review MED 5), so this
  // fallback is the path actually taken in production — and
  // `/v0.1/servers/<name>` 404s live ("Endpoint not found"); the readable
  // listing is `/v0.1/servers/<name>/versions` (confirmed 200 live).
  return { url: body.url ?? `${registryUrl}/v0.1/servers/${encodeURIComponent(serverJson.name)}/versions` };
}
