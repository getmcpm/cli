/**
 * Registry publish client — wraps the POST submit endpoint.
 * Shares timeout/error infrastructure with RegistryClient.
 */

import type { PublishManifest } from "../commands/publish/manifest.js";
import type { SubmitResult } from "../commands/publish/submit.js";
import { NetworkError, RegistryError } from "./errors.js";

const DEFAULT_TIMEOUT_MS = 15_000;

export async function submitToRegistry(
  manifest: PublishManifest,
  token: string,
  registryUrl: string
): Promise<SubmitResult> {
  const controller = new AbortController();
  const timerId = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  const url = `${registryUrl}/v0.1/servers`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
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

  if (!response.ok) {
    throw new RegistryError(`Registry API returned ${response.status}`, response.status);
  }

  const body = await response.json() as { url?: string };
  return { url: body.url ?? `${registryUrl}/servers/${encodeURIComponent(manifest.name)}` };
}
