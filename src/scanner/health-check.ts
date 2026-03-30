/**
 * Post-install health check — spawns an MCP server and verifies it responds.
 *
 * Three tiers:
 * 1. Config validation (entry has command or url) — always passes if we got here
 * 2. Process start (spawn + initialize handshake) — verifies the binary exists
 * 3. Tool listing (tools/list call) — verifies the server actually works
 *
 * Returns a HealthCheckResult. Never throws — failures are reported, not fatal.
 */

import { spawn } from "node:child_process";
import type { McpServerEntry } from "../config/adapters/index.js";

// ---------------------------------------------------------------------------
// Environment sanitization for health checks
// ---------------------------------------------------------------------------

/**
 * Environment variables that should NOT be passed to untrusted MCP servers
 * during health checks. The health check only needs the server to start and
 * respond to tools/list — it does not need access to the user's secrets.
 *
 * Pattern: known secret variable names from major cloud providers, AI APIs,
 * CI systems, and databases. Uses exact matches (case-insensitive compare).
 */
const SENSITIVE_ENV_PREFIXES: readonly string[] = [
  "AWS_SECRET",
  "AWS_SESSION",
  "AZURE_CLIENT_SECRET",
  "AZURE_TENANT",
  "GCP_SERVICE_ACCOUNT",
  "GOOGLE_APPLICATION_CREDENTIALS",
];

const SENSITIVE_ENV_NAMES: ReadonlySet<string> = new Set([
  // Cloud provider secrets
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  // AI API keys
  "ANTHROPIC_API_KEY",
  "OPENAI_API_KEY",
  "GOOGLE_API_KEY",
  // VCS tokens
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITLAB_TOKEN",
  "BITBUCKET_TOKEN",
  // Package registry tokens
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "PYPI_TOKEN",
  // Database
  "DATABASE_URL",
  "DB_PASSWORD",
  "PGPASSWORD",
  "MYSQL_PWD",
  "REDIS_PASSWORD",
  // CI/CD
  "CI_JOB_TOKEN",
  "CIRCLE_TOKEN",
  "TRAVIS_TOKEN",
  // Generic
  "SECRET_KEY",
  "PRIVATE_KEY",
  "ENCRYPTION_KEY",
  "API_SECRET",
  "AUTH_TOKEN",
]);

/**
 * Build a sanitized environment for health check subprocesses.
 * Strips known sensitive variables from process.env before merging
 * the server's declared env vars (which may legitimately need API keys
 * the user provided during install).
 */
function buildHealthCheckEnv(
  serverEnv?: Record<string, string>,
  extraEnv?: Record<string, string>
): Record<string, string> {
  const base: Record<string, string> = {};

  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    const upper = key.toUpperCase();
    if (SENSITIVE_ENV_NAMES.has(upper)) continue;
    if (SENSITIVE_ENV_PREFIXES.some((p) => upper.startsWith(p))) continue;
    base[key] = value;
  }

  // Merge caller-provided env and server-declared env on top.
  // Server env vars (e.g. API keys the user typed during install) are
  // intentionally NOT filtered — the user explicitly provided them.
  return { ...base, ...(extraEnv ?? {}), ...(serverEnv ?? {}) };
}

export interface HealthCheckResult {
  tier: 1 | 2 | 3;
  passed: boolean;
  toolCount: number | null;
  error: string | null;
  durationMs: number;
}

/**
 * Run a health check against an installed MCP server entry.
 *
 * For stdio servers (command + args): spawns the process, sends initialize
 * and tools/list via JSON-RPC over stdin, reads the response.
 *
 * For HTTP servers (url): skipped (tier 1 only, config validation).
 *
 * Timeout: 15 seconds. If the server doesn't respond, the check fails
 * gracefully with an error message.
 */
export async function runHealthCheck(
  entry: McpServerEntry,
  env?: Record<string, string>
): Promise<HealthCheckResult> {
  const start = Date.now();

  // Tier 1: config validation — if we have an entry, it passed
  if ("url" in entry && typeof entry.url === "string") {
    return {
      tier: 1,
      passed: true,
      toolCount: null,
      error: null,
      durationMs: Date.now() - start,
    };
  }

  if (!("command" in entry) || typeof entry.command !== "string") {
    return {
      tier: 1,
      passed: false,
      toolCount: null,
      error: "No command or URL in server entry",
      durationMs: Date.now() - start,
    };
  }

  // Tier 2+3: spawn the server, send initialize + tools/list
  const command = entry.command;
  const args = ("args" in entry && Array.isArray(entry.args)) ? entry.args : [];

  const initRequest = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "mcpm-health-check", version: "1.0" },
    },
  });

  const initializedNotification = JSON.stringify({
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });

  const toolsRequest = JSON.stringify({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/list",
  });

  const input = `${initRequest}\n${initializedNotification}\n${toolsRequest}\n`;

  const mergedEnv = buildHealthCheckEnv(entry.env, env);

  return new Promise<HealthCheckResult>((resolve) => {
    const child = spawn(command, [...args], {
      env: mergedEnv,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    const timeout = setTimeout(() => {
      child.kill();
      resolve({
        tier: 2,
        passed: false,
        toolCount: null,
        error: "Server did not respond within 15 seconds",
        durationMs: Date.now() - start,
      });
    }, 15_000);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.on("error", (err) => {
      clearTimeout(timeout);
      resolve({
        tier: 2,
        passed: false,
        toolCount: null,
        error: `Failed to start server: ${err.message}`,
        durationMs: Date.now() - start,
      });
    });

    child.on("close", () => {
      clearTimeout(timeout);

      if (!stdout.trim()) {
        resolve({
          tier: 2,
          passed: false,
          toolCount: null,
          error: "Server started but returned no output",
          durationMs: Date.now() - start,
        });
        return;
      }

      const lines = stdout.trim().split("\n");
      let toolCount: number | null = null;

      for (const line of lines) {
        try {
          const msg = JSON.parse(line) as {
            id?: number;
            result?: { tools?: unknown[] };
          };
          if (msg.id === 2 && msg.result?.tools) {
            toolCount = msg.result.tools.length;
          }
        } catch {
          // skip non-JSON lines
        }
      }

      if (toolCount !== null) {
        resolve({
          tier: 3,
          passed: true,
          toolCount,
          error: null,
          durationMs: Date.now() - start,
        });
        return;
      }

      resolve({
        tier: 2,
        passed: true,
        toolCount: null,
        error: "Server responded to initialize but not tools/list",
        durationMs: Date.now() - start,
      });
    });

    // Send JSON-RPC messages to stdin
    child.stdin.write(input);
    child.stdin.end();
  });
}
