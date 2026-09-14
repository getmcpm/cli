/**
 * `mcpm publish` — submit to the official MCP registry.
 * Token is read from GITHUB_TOKEN or MCPM_TOKEN env only (never from CLI flags),
 * unless --github-oidc is passed, in which case a GitHub Actions OIDC token is
 * minted and exchanged instead (see fetchActionsOidcToken/exchangeGitHubOidcToken).
 *
 * A GitHub token/PAT and a GitHub Actions OIDC token are never sent to the
 * registry's publish endpoint directly — both are exchanged for a short-lived
 * registry JWT first (POST /v0.1/auth/github-at or /v0.1/auth/github-oidc),
 * and only that JWT is sent to POST /v0.1/publish.
 */

import chalk from "chalk";
import type { PublishManifest, ServerJson } from "./manifest.js";
import type { ServerEntry } from "../../registry/types.js";
import type { Finding } from "../../scanner/tier1.js";
import type { RegistryTokenResponse } from "../../registry/publish-client.js";
import { PublishErrors } from "../../errors/publish-errors.js";
import { manifestToEntry, assertTrustGate } from "./check.js";
import { manifestToServerJson, resolveVersion } from "./manifest.js";
import { validateRegistryUrl } from "../../registry/publish-client.js";

export interface SubmitResult {
  url: string;
}

export interface PublishSubmitDeps {
  readManifest: () => Promise<PublishManifest | null>;
  scanTier1: (entry: ServerEntry) => Finding[];
  submitToRegistry: (serverJson: ServerJson, registryToken: string, registryUrl: string) => Promise<SubmitResult>;
  exchangeGitHubToken: (registryUrl: string, githubToken: string) => Promise<RegistryTokenResponse>;
  exchangeGitHubOidcToken: (registryUrl: string, oidcToken: string) => Promise<RegistryTokenResponse>;
  fetchActionsOidcToken: (audience: string, env: Record<string, string | undefined>) => Promise<string>;
  audienceFromRegistryUrl: (registryUrl: string) => string;
  getToken: () => string | null;
  output: (text: string) => void;
  env?: Record<string, string | undefined>;
  cwd?: string;
}

export interface PublishSubmitOptions {
  registryUrl?: string;
  githubOidc?: boolean;
}

const DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io";

export async function handlePublishSubmit(
  options: PublishSubmitOptions,
  deps: PublishSubmitDeps
): Promise<void> {
  const {
    readManifest,
    scanTier1,
    submitToRegistry,
    exchangeGitHubToken,
    exchangeGitHubOidcToken,
    fetchActionsOidcToken,
    audienceFromRegistryUrl,
    getToken,
    output,
    env = process.env,
    cwd = process.cwd(),
  } = deps;
  const registryUrl = options.registryUrl ?? DEFAULT_REGISTRY;
  // Before anything else: a malformed/unsafe --registry must not cause a
  // real GitHub Actions OIDC mint (fetchActionsOidcToken hits GitHub's own
  // token endpoint) or a wasted registry round-trip further down (#216
  // review, NIT 14). exchangeGitHubToken/exchangeGitHubOidcToken/
  // submitToRegistry each re-validate before their own network call, so
  // this is defense-in-depth for the steps between here and there, not a
  // replacement for those checks.
  validateRegistryUrl(registryUrl);

  const manifest = await readManifest();
  if (!manifest) throw PublishErrors.manifestNotFound();

  assertTrustGate(scanTier1(manifestToEntry(manifest)));

  // Resolve the version BEFORE any token exchange (#216 review, NIT 14): a
  // missing version (no manifest `version`, no package.json in cwd) must
  // fail before burning a registry JWT exchange or minting a real GitHub
  // Actions OIDC token — both are real network calls with side effects
  // (an OIDC mint is scoped/logged; a registry token exchange is a live
  // round-trip), wasted entirely if resolveVersion is about to throw.
  const version = await resolveVersion(manifest, cwd);

  const registryToken = options.githubOidc
    ? (await exchangeGitHubOidcToken(registryUrl, await fetchActionsOidcToken(audienceFromRegistryUrl(registryUrl), env)))
        .registryToken
    : await (async () => {
        const token = getToken();
        if (!token) throw PublishErrors.tokenRequired();
        return (await exchangeGitHubToken(registryUrl, token)).registryToken;
      })();

  const serverJson = manifestToServerJson(manifest, version);

  const result = await submitToRegistry(serverJson, registryToken, registryUrl);
  output(chalk.green(`\nPublished successfully!`));
  output(`  Registry URL: ${chalk.cyan(result.url)}`);
}

/** Read GitHub token from environment only. Never from CLI flags. */
export function getTokenFromEnv(): string | null {
  return process.env.GITHUB_TOKEN ?? process.env.MCPM_TOKEN ?? null;
}
