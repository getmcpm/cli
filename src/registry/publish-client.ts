/**
 * Registry publish client — wraps the POST submit endpoint.
 * Shares timeout/error infrastructure with RegistryClient.
 */

import type { PublishManifest } from "../commands/publish/manifest.js";
import type { SubmitResult } from "../commands/publish/submit.js";
import { NetworkError, RegistryError } from "./errors.js";

const DEFAULT_TIMEOUT_MS = 15_000;

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
  }
  if (h.startsWith("fc") || h.startsWith("fd") || h.startsWith("fe80")) return true; // IPv6 ULA/link-local
  return false;
}

export async function submitToRegistry(
  manifest: PublishManifest,
  token: string,
  registryUrl: string
): Promise<SubmitResult> {
  validateRegistryUrl(registryUrl);

  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  const url = `${registryUrl}/v0.1/servers`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      // redirect:"manual" — a 3xx must NOT carry the Authorization token to the
      // redirect target. A redirect surfaces as a non-ok response and errors below.
      redirect: "manual",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(manifest),
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

  if (response.type === "opaqueredirect" || response.status === 0) {
    throw new RegistryError(
      "Registry attempted a redirect (3xx); refusing to follow it with the auth token. Check the --registry URL.",
      0
    );
  }

  if (!response.ok) {
    throw new RegistryError(`Registry API returned ${response.status}`, response.status);
  }

  const body = await response.json() as { url?: string };
  return { url: body.url ?? `${registryUrl}/servers/${encodeURIComponent(manifest.name)}` };
}
