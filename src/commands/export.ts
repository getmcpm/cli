/**
 * `mcpm export` command handler.
 *
 * Reads installed MCP servers across all detected clients and produces
 * an mcpm.yaml stack file. Deduplicates by server name (first-seen-wins).
 * Env var keys are exported without values; secret status is inferred
 * from common naming patterns (TOKEN, KEY, SECRET, PASSWORD).
 *
 * Exports:
 * - handleExport()           — injectable handler for testing
 * - registerExportCommand()  — Commander registration
 */

import type { ClientId } from "../config/paths.js";
import type { ConfigAdapter, McpServerEntry } from "../config/adapters/index.js";
import type { StackFile, StackEnvVar } from "../stack/schema.js";
import { serializeYaml } from "../stack/schema.js";
import { sanitizeForTerminal } from "../guard/sanitize.js";
import { DEFAULT_MIN_RELEASE_AGE_HOURS } from "../scanner/cooldown.js";

// ---------------------------------------------------------------------------
// Secret inference
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  /TOKEN/i,
  /KEY/i,
  /SECRET/i,
  /PASSWORD/i,
  /CREDENTIAL/i,
  /AUTH/i,
];

function inferSecret(envName: string): boolean {
  return SECRET_PATTERNS.some((p) => p.test(envName));
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ExportOptions {
  output?: string;
}

export interface ExportDeps {
  detectClients: () => Promise<ClientId[]>;
  getAdapter: (clientId: ClientId) => Pick<ConfigAdapter, "read">;
  getPath: (clientId: ClientId) => string;
  writeFile: (path: string, content: string) => Promise<void>;
  output: (text: string) => void;
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/**
 * Core handler for `mcpm export`.
 *
 * Reads installed servers across all detected clients, deduplicates by name
 * (first-seen-wins by client detection order), and produces mcpm.yaml.
 */
export async function handleExport(
  options: ExportOptions,
  deps: ExportDeps
): Promise<void> {
  const { detectClients, getAdapter, getPath, writeFile, output } = deps;

  const clients = await detectClients();
  const seen = new Set<string>();
  // #65: Object.create(null), not a literal — see base.ts's read(). `name` is
  // config-supplied, and plain assignment of `__proto__` sets this object's
  // prototype instead of adding a key, so the server disappeared from the
  // stack file the user then keeps as their declaration of record. Silently:
  // it is well-formed, so nothing reports it.
  const servers: Record<string, { entry: McpServerEntry }> = {};
  // #59: an entry read() dropped for failing shape validation is silently
  // ABSENT from the export — and the user keeps the result as their declared
  // stack. Name them on stderr so the file is never mistaken for complete
  // (stderr, not `output`: with no --output the YAML itself goes to stdout).
  const unreadable: string[] = [];
  // #65: `__proto__` is the ONE name this format cannot round-trip, so this is
  // a flag, not a list. Kept separate from `unreadable` — those entries are
  // malformed, this one is perfectly valid and the client launches it; only
  // mcpm.yaml can't name it. No sanitizeForTerminal: the only value that can
  // reach the message is that compile-time constant, not the config's string.
  let sawProtoName = false;

  for (const clientId of clients) {
    try {
      const adapter = getAdapter(clientId);
      const configPath = getPath(clientId);
      const installed = await adapter.read(configPath, (name) => {
        if (!unreadable.includes(name)) unreadable.push(name);
      });

      for (const [name, entry] of Object.entries(installed)) {
        if (name === "__proto__") {
          // #65: read() now surfaces this entry (it used to vanish into the
          // accumulator's prototype), but mcpm.yaml cannot carry it: the stack
          // schema's `z.record` DROPS the key `__proto__` on parse — measured,
          // and only that name; `constructor`/`prototype`/`toString` survive.
          // Emitting it would write a file that reads back one server short,
          // so `up` would install part of a stack it called complete. Name it
          // instead. The client still runs the server; renaming it in the
          // client config is the fix, and only the user can make that call.
          sawProtoName = true;
          // Record it as CONTRIBUTED even though it is not exported. The
          // `omitted` filter below reads `seen` to decide whether a name that
          // one client reported as malformed was supplied intact by another —
          // without this, a client holding a malformed copy makes export ALSO
          // print "could not be read", which is false, and is the exact false
          // statement the #59 paragraph below was written to prevent for every
          // other name. The reason this entry is missing is stated once, by
          // the message below, and it is not "malformed".
          seen.add(name);
          continue;
        }
        if (seen.has(name)) continue;
        seen.add(name);
        servers[name] = { entry: { ...entry } };
      }
    } catch {
      // Skip clients with unreadable configs
    }
  }

  // A name is only ABSENT from the export if no client contributed a readable
  // entry for it — another client holding a well-formed copy makes the export
  // complete, and saying otherwise is its own false statement (caught by
  // dogfooding: cursor's good copy of a claude-desktop-malformed server).
  // `name in servers` walks the PROTOTYPE CHAIN, so an entry named `toString`
  // / `constructor` / `valueOf` read as already-exported and vanished from both
  // the warning and the file. Server names are arbitrary JSON keys. `seen` is
  // the Set of names actually contributed, and has no such members.
  const omitted = unreadable.filter((name) => !seen.has(name));
  if (omitted.length > 0) {
    process.stderr.write(
      `mcpm: ${omitted.length} server ${omitted.length === 1 ? "entry" : "entries"} ` +
        `could not be read and ${omitted.length === 1 ? "is" : "are"} NOT in this export: ` +
        `${omitted.map((n) => sanitizeForTerminal(n)).join(", ")}. ` +
        `Run \`mcpm doctor\` for details.\n`
    );
  }

  if (sawProtoName) {
    process.stderr.write(
      `mcpm: the server named "__proto__" is NOT in this export — mcpm.yaml ` +
        `cannot represent that name. Rename it in the client config to include it.\n`
    );
  }

  const stackFile = buildStackFile(servers);
  const yaml = serializeYaml(stackFile);

  if (options.output) {
    await writeFile(options.output, yaml);
    output(`Exported ${Object.keys(servers).length} servers to ${options.output}`);
  } else {
    output(yaml);
  }
}

// ---------------------------------------------------------------------------
// Stack file builder
// ---------------------------------------------------------------------------

function buildStackFile(
  servers: Record<string, { entry: McpServerEntry }>
): StackFile {
  // #65: Object.create(null) like every other name-keyed accumulator here.
  // handleExport filters `__proto__` before this runs, so no test can currently
  // distinguish this from a literal — kept anyway because the correct form
  // costs one word, and a literal here would silently ABSORB the name if the
  // filter above were ever removed, turning a loud bug into an invisible one.
  // That is not hypothetical: it is the third instance of this exact swallow in
  // this codebase (read(), the dedupe map above, and here).
  const stackServers: StackFile["servers"] = Object.create(null);

  for (const [name, { entry }] of Object.entries(servers)) {
    if (entry.url) {
      // URL-based server
      stackServers[name] = {
        url: entry.url,
        ...(entry.env ? { env: buildEnvDeclarations(entry.env) } : {}),
      };
    } else {
      // Registry-based server (version unknown from config, use latest)
      stackServers[name] = {
        version: "latest",
        ...(entry.env ? { env: buildEnvDeclarations(entry.env) } : {}),
      };
    }
  }

  return {
    version: "1",
    // F4 curated default: 24h release cooldown for newly generated stacks. NOTE: arming
    // minReleaseAgeHours also fail-closes `up` on servers with NO publish timestamp
    // (deliberate — see cooldown.ts split semantics); the policy reason names the fix.
    policy: {
      blockOnScoreDrop: false,
      minReleaseAgeHours: DEFAULT_MIN_RELEASE_AGE_HOURS,
    },
    servers: stackServers,
  };
}

function buildEnvDeclarations(
  env: Record<string, string>
): Record<string, StackEnvVar> {
  const declarations: Record<string, StackEnvVar> = {};

  for (const key of Object.keys(env)) {
    declarations[key] = {
      required: true,
      secret: inferSecret(key),
    };
  }

  return declarations;
}

// ---------------------------------------------------------------------------
// Commander registration
// ---------------------------------------------------------------------------

import { Command } from "commander";
import { writeFile as fsWriteFile } from "fs/promises";
import { detectInstalledClients } from "../config/detector.js";
import { getConfigPath } from "../config/paths.js";
import { getAdapter as getAdapterDefault } from "../config/index.js";
import { stdoutOutput } from "../utils/output.js";

export function registerExportCommand(program: Command): void {
  program
    .command("export")
    .description("Export installed MCP servers as an mcpm.yaml stack file")
    .option("-o, --output <file>", "write to file instead of stdout")
    .action(async (opts: { output?: string }) => {
      const chalk = (await import("chalk")).default;
      try {
        await handleExport(
          { output: opts.output },
          {
            detectClients: detectInstalledClients,
            getAdapter: getAdapterDefault,
            getPath: getConfigPath,
            writeFile: (path, content) =>
              fsWriteFile(path, content, { encoding: "utf-8", mode: 0o600 }),
            output: stdoutOutput,
          }
        );
      } catch (err) {
        console.error(chalk.red((err as Error).message));
        process.exit(1);
      }
    });
}
