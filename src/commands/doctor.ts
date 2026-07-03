/**
 * `mcpm doctor` command handler.
 *
 * Checks MCP setup health and reports issues:
 * - Which AI clients have config files
 * - Whether config files are valid JSON
 * - Which runtimes (npx, uvx, docker) are available
 * - Whether installed servers reference available runtimes
 *
 * Returns 0 for no critical issues, 1 for critical issues.
 * All external dependencies are injected for testability.
 *
 * D7: the check logic is split into a pure `buildDoctorModel` (a structured
 * `DoctorModel`) and renderers. `--json` emits the model; `--report` emits a
 * redacted, name-free env snapshot for bug reports; the MCP-server `handleDoctor`
 * reuses the same model (fixing its formerly-hardcoded `issues: []`).
 */

import { access } from "fs/promises";
import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { detectInstalledClients } from "../config/detector.js";
import type { getConfigPath } from "../config/paths.js";
import { buildDriftModel, type ClientState } from "../config/drift.js";
import { isWrapped } from "../guard/wrap.js";

// ---------------------------------------------------------------------------
// Deps interface
// ---------------------------------------------------------------------------

export interface DoctorDeps {
  detectClients: typeof detectInstalledClients;
  getAdapter: (clientId: ClientId) => ConfigAdapter;
  getConfigPath: typeof getConfigPath;
  /** Returns true if the config file exists for this client. */
  checkConfigExists: (clientId: ClientId) => Promise<boolean>;
  /** Returns true if the given executable is available on PATH. */
  execCheck: (cmd: string) => Promise<boolean>;
  output: (text: string) => void;
}

/** The subset of deps the pure model builder needs (no output, no detector). */
export type DoctorModelDeps = Pick<
  DoctorDeps,
  "getAdapter" | "getConfigPath" | "checkConfigExists" | "execCheck"
>;

// ---------------------------------------------------------------------------
// Structured model (D7 — one shape for text/json/report/MCP consumers)
// ---------------------------------------------------------------------------

export interface DoctorClientHealth {
  id: ClientId;
  label: string;
  exists: boolean;
  malformed: boolean;
  serverCount: number;
  /** Servers wrapped by the guard relay (subset of serverCount). */
  guardedCount: number;
}

export interface DoctorRuntimeHealth {
  name: Runtime;
  available: boolean;
}

export interface DoctorDriftEntry {
  name: string;
  kind: "conflict" | "absent";
  present: string[];
  absent: string[];
  /** Present only for `kind: "conflict"`. */
  fields?: string[];
}

export interface DoctorCrossClient {
  consistent: boolean;
  clientCount: number;
  serverCount: number;
  drift: DoctorDriftEntry[];
}

export interface DoctorIssue {
  kind: "malformed-config" | "missing-runtime";
  message: string;
}

export interface DoctorModel {
  schemaVersion: 1;
  clients: DoctorClientHealth[];
  runtimes: DoctorRuntimeHealth[];
  /** Advisory cross-client consistency; null when <2 clients have a readable config. */
  crossClient: DoctorCrossClient | null;
  /** Critical issues — these drive the exit code. */
  issues: DoctorIssue[];
  /** true iff issues is empty. */
  ok: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RUNTIMES = ["npx", "uvx", "docker"] as const;

type Runtime = (typeof RUNTIMES)[number];

const CLIENT_LABELS: Record<ClientId, string> = {
  "claude-desktop": "Claude Desktop",
  "claude-code": "Claude Code",
  cursor: "Cursor",
  vscode: "VS Code",
  windsurf: "Windsurf",
  "gemini-cli": "Gemini CLI",
};

const RUNTIME_INSTALL_HINTS: Record<Runtime, string> = {
  npx: "install Node.js from https://nodejs.org",
  uvx: "install uv from https://docs.astral.sh/uv/",
  docker: "install Docker from https://docs.docker.com/get-docker/",
};

// ---------------------------------------------------------------------------
// Model builder (pure — no output)
// ---------------------------------------------------------------------------

interface ClientRead {
  exists: boolean;
  malformed: boolean;
  servers: Record<string, McpServerEntry> | null;
}

/**
 * Runs every health check and returns the structured model. No side effects
 * beyond the injected reads; safe to call from the CLI, `--json`, `--report`,
 * and the MCP `handleDoctor` tool.
 */
export async function buildDoctorModel(deps: DoctorModelDeps): Promise<DoctorModel> {
  const { getAdapter, getConfigPath, checkConfigExists, execCheck } = deps;

  // 1. Read each known client's config.
  const reads = await Promise.all(
    CLIENT_IDS.map(async (clientId): Promise<{ clientId: ClientId; read: ClientRead }> => {
      const exists = await checkConfigExists(clientId);
      if (!exists) return { clientId, read: { exists: false, malformed: false, servers: null } };
      try {
        const servers = await getAdapter(clientId).read(getConfigPath(clientId));
        return { clientId, read: { exists: true, malformed: false, servers } };
      } catch {
        return { clientId, read: { exists: true, malformed: true, servers: null } };
      }
    })
  );

  const issues: DoctorIssue[] = [];

  const clients: DoctorClientHealth[] = reads.map(({ clientId, read }) => {
    const label = CLIENT_LABELS[clientId];
    if (read.malformed) {
      issues.push({
        kind: "malformed-config",
        message: `Config file for ${label} is malformed — fix the JSON syntax.`,
      });
    }
    const servers = read.servers ?? {};
    const entries = Object.values(servers);
    return {
      id: clientId,
      label,
      exists: read.exists,
      malformed: read.malformed,
      serverCount: entries.length,
      guardedCount: entries.filter(isWrapped).length,
    };
  });

  // 2. Runtime availability.
  const runtimes: DoctorRuntimeHealth[] = await Promise.all(
    RUNTIMES.map(async (name) => ({ name, available: await execCheck(name) }))
  );
  const runtimeAvailable = new Map(runtimes.map((r) => [r.name as string, r.available]));

  // 3. Cross-check: servers whose command is a tracked-but-unavailable runtime.
  for (const { clientId, read } of reads) {
    if (!read.servers) continue;
    for (const [serverName, entry] of Object.entries(read.servers)) {
      const cmd = entry.command;
      if (!cmd) continue; // HTTP/URL server — no runtime needed.
      if (RUNTIMES.includes(cmd as Runtime) && runtimeAvailable.get(cmd) === false) {
        issues.push({
          kind: "missing-runtime",
          message: `Server '${serverName}' in ${CLIENT_LABELS[clientId]} uses '${cmd}' but ${cmd} is not installed.`,
        });
      }
    }
  }

  // 4. Cross-client consistency (advisory — never an issue, never fails doctor).
  const driftStates: ClientState[] = reads.flatMap(({ clientId, read }) =>
    read.servers ? [{ clientId, servers: read.servers }] : []
  );
  const crossClient = driftStates.length >= 2 ? toCrossClient(driftStates) : null;

  return { schemaVersion: 1, clients, runtimes, crossClient, issues, ok: issues.length === 0 };
}

function toCrossClient(states: ClientState[]): DoctorCrossClient {
  const drift = buildDriftModel(states);
  const entries: DoctorDriftEntry[] = [];
  for (const server of drift.servers) {
    // buildDriftModel returns readonly arrays — copy into the mutable public model.
    if (server.conflict) {
      entries.push({
        name: server.name,
        kind: "conflict",
        present: [...server.present],
        absent: [...server.absent],
        fields: server.conflictFields ? [...server.conflictFields] : undefined,
      });
    } else if (server.absent.length > 0) {
      entries.push({
        name: server.name,
        kind: "absent",
        present: [...server.present],
        absent: [...server.absent],
      });
    }
  }
  return {
    consistent: drift.drifted === 0,
    clientCount: drift.clients.length,
    serverCount: drift.servers.length,
    drift: entries,
  };
}

// ---------------------------------------------------------------------------
// Human-readable renderer (byte-identical to the pre-D7 output)
// ---------------------------------------------------------------------------

export function renderDoctorText(model: DoctorModel, output: (text: string) => void): void {
  output("");
  output("mcpm doctor");
  output("");

  for (const c of model.clients) {
    if (!c.exists) {
      output(`  ✗ ${c.label} — config not found`);
    } else if (c.malformed) {
      output(`  ✗ ${c.label} — config malformed (JSON parse error)`);
    } else {
      const word = c.serverCount === 1 ? "server" : "servers";
      output(`  ✓ ${c.label} — config found, ${c.serverCount} ${word}`);
    }
  }

  output("");
  output("Runtimes:");
  for (const r of model.runtimes) {
    if (r.available) {
      output(`  ✓ ${r.name} available`);
    } else {
      output(`  ✗ ${r.name} not found — ${RUNTIME_INSTALL_HINTS[r.name]}`);
    }
  }

  if (model.crossClient) {
    const cc = model.crossClient;
    output("");
    output("Cross-client (advisory):");
    if (cc.consistent) {
      const word = cc.serverCount === 1 ? "server" : "servers";
      output(`  ✓ ${cc.serverCount} ${word} consistent across ${cc.clientCount} clients`);
    } else {
      for (const d of cc.drift) {
        if (d.kind === "conflict") {
          output(`  ⚠ ${d.name} — config differs (${d.fields!.join(", ")}) across ${d.present.join(", ")}`);
        } else {
          output(`  ⚠ ${d.name} — in ${d.present.join(", ")}; missing in ${d.absent.join(", ")}`);
        }
      }
      output("  Run `mcpm sync --check` for the full matrix (advisory, not a failure).");
    }
  }

  if (model.issues.length > 0) {
    output("");
    output("Issues:");
    for (const issue of model.issues) {
      output(`  ⚠ ${issue.message}`);
    }
    output("");
    output("Critical issues found. Run the commands above to resolve them.");
    return;
  }

  output("");
  output("No critical issues found.");
}

// ---------------------------------------------------------------------------
// Redacted report (D7 — pasteable env snapshot, NO server names/args)
// ---------------------------------------------------------------------------

export interface DoctorReportEnv {
  mcpm: string;
  node: string;
  platform: string;
  arch: string;
  osRelease: string;
  confineBackend: boolean;
  secretStore: "os-keychain" | "machine-key";
}

export interface DoctorReport {
  schemaVersion: 1;
  mcpm: string;
  node: string;
  os: string;
  confineBackend: boolean;
  secretStore: "os-keychain" | "machine-key";
  clients: Array<Omit<DoctorClientHealth, "label">>;
  runtimes: DoctorRuntimeHealth[];
  /** Counts only — issue messages embed server names, so they are NOT included. */
  issues: { malformedConfigs: number; missingRuntime: number };
}

export function buildDoctorReport(model: DoctorModel, env: DoctorReportEnv): DoctorReport {
  return {
    schemaVersion: 1,
    mcpm: env.mcpm,
    node: env.node,
    os: `${env.platform} ${env.arch} ${env.osRelease}`,
    confineBackend: env.confineBackend,
    secretStore: env.secretStore,
    // Redaction: drop the label + every server name; keep only counts.
    clients: model.clients.map(({ id, exists, malformed, serverCount, guardedCount }) => ({
      id,
      exists,
      malformed,
      serverCount,
      guardedCount,
    })),
    runtimes: model.runtimes,
    issues: {
      malformedConfigs: model.issues.filter((i) => i.kind === "malformed-config").length,
      missingRuntime: model.issues.filter((i) => i.kind === "missing-runtime").length,
    },
  };
}

export function renderReportText(r: DoctorReport): string {
  const lines: string[] = [];
  lines.push("mcpm doctor --report (redacted — no server names or args)");
  lines.push(`mcpm:            ${r.mcpm}`);
  lines.push(`node:            ${r.node}`);
  lines.push(`os:              ${r.os}`);
  lines.push(`confine backend: ${r.confineBackend ? "available" : "unavailable"}`);
  lines.push(`secret store:    ${r.secretStore}`);
  lines.push("");
  lines.push("clients:");
  for (const c of r.clients) {
    if (!c.exists) {
      lines.push(`  ${c.id}: not found`);
    } else if (c.malformed) {
      lines.push(`  ${c.id}: config malformed`);
    } else {
      const guarded = c.guardedCount > 0 ? `, ${c.guardedCount} guarded` : "";
      lines.push(`  ${c.id}: ${c.serverCount} servers${guarded}`);
    }
  }
  lines.push("runtimes:");
  for (const rt of r.runtimes) {
    lines.push(`  ${rt.name}: ${rt.available ? "available" : "missing"}`);
  }
  lines.push(
    `issues: ${r.issues.malformedConfigs} malformed config(s), ${r.issues.missingRuntime} missing-runtime`
  );
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export interface DoctorOpts {
  json?: boolean;
  report?: boolean;
  /** Injected in --report mode; the Commander action supplies the real env. */
  reportEnv?: DoctorReportEnv;
}

/**
 * Core logic for `mcpm doctor`.
 * @returns Exit code: 0 = healthy, 1 = critical issues found.
 */
export async function doctorHandler(deps: DoctorDeps, opts: DoctorOpts = {}): Promise<number> {
  const model = await buildDoctorModel(deps);

  if (opts.report) {
    const env = opts.reportEnv ?? gatherReportEnv();
    deps.output(renderReportText(buildDoctorReport(model, env)));
  } else if (opts.json) {
    deps.output(JSON.stringify(model, null, 2));
  } else {
    renderDoctorText(model, deps.output);
  }

  return model.ok ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import chalk from "chalk";
import os from "os";
import { execFile } from "child_process";
import { detectInstalledClients as _detectClients } from "../config/detector.js";
import { getConfigPath as _getConfigPath, CLIENT_IDS } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { isConfineBackendAvailable } from "../guard/confine/apply.js";
import { isSupportedPlatform as isKeychainSupported } from "../store/os-keychain.js";

/** Factory so callers that inject a custom getConfigPath (e.g. the MCP server) get honored. */
export function makeCheckConfigExists(
  getConfigPathFn: (clientId: ClientId) => string
): (clientId: ClientId) => Promise<boolean> {
  return async (clientId: ClientId): Promise<boolean> => {
    try {
      await access(getConfigPathFn(clientId));
      return true;
    } catch {
      return false;
    }
  };
}

const checkConfigExistsDefault = makeCheckConfigExists(_getConfigPath);

const ALLOWED_RUNTIME_CMDS = new Set<string>(["npx", "uvx", "docker"]);

export function execCheckDefault(cmd: string): Promise<boolean> {
  if (!ALLOWED_RUNTIME_CMDS.has(cmd)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const which = process.platform === "win32" ? "where" : "which";
    execFile(which, [cmd], (err) => {
      resolve(err === null);
    });
  });
}

/** Gathers the impure environment fields for `--report`. */
function gatherReportEnv(): DoctorReportEnv {
  return {
    mcpm: __PKG_VERSION__,
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    osRelease: os.release(),
    confineBackend: isConfineBackendAvailable(),
    secretStore: isKeychainSupported() ? "os-keychain" : "machine-key",
  };
}

function coloredOutput(text: string): void {
  if (text.startsWith("  ✓")) {
    console.log(chalk.green(text));
  } else if (text.startsWith("  ✗")) {
    console.log(chalk.red(text));
  } else if (text.startsWith("  ⚠")) {
    console.log(chalk.yellow(text));
  } else {
    console.log(text);
  }
}

export function registerDoctorCommand(program: Command): void {
  program
    .command("doctor")
    .description("Check MCP setup health and report issues")
    .option("--json", "emit the structured DoctorModel as JSON (shape UNSTABLE; NOT redacted — includes server names, use --report to share publicly)")
    .option("--report", "emit a redacted, pasteable env snapshot for bug reports (no server names/args)")
    .action(async (options: { json?: boolean; report?: boolean }) => {
      // --json / --report are machine/paste output — never colorize.
      const plain = options.json || options.report;
      const deps: DoctorDeps = {
        detectClients: _detectClients,
        getAdapter: getAdapterDefault,
        getConfigPath: _getConfigPath,
        checkConfigExists: checkConfigExistsDefault,
        execCheck: execCheckDefault,
        output: plain ? (t) => console.log(t) : coloredOutput,
      };

      const exitCode = await doctorHandler(deps, { json: options.json, report: options.report });
      process.exit(exitCode);
    });
}
