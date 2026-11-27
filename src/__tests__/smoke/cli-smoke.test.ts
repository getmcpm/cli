/**
 * CLI output-contract smoke matrix — the dogfood, shifted left.
 *
 * Spawns the BUILT binary (dist/index.js) in a throwaway HOME and asserts the
 * user-facing OUTPUT on edge paths: the "no-op / not-found" paths where commands
 * historically printed false success ("refreshed" / "Removed secret") while their
 * helper actually did nothing. Structural unit tests pass right past that class;
 * only an end-to-end output assertion catches it. Local-only commands (no registry)
 * so the matrix is deterministic and offline.
 *
 * CI builds (`pnpm run build`) before tests, so dist is fresh there. Locally we
 * build once if dist is missing — run `npm run build` first if iterating on a
 * command, since a stale dist would test old code.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { spawnSync, execSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, existsSync, mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { parse as parseYaml } from "yaml";

const BIN = path.resolve(process.cwd(), "dist/index.js");

beforeAll(() => {
  if (!existsSync(BIN)) {
    execSync("npm run build", { cwd: process.cwd(), timeout: 180_000, stdio: "ignore" });
  }
}, 200_000);

interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
  /** stdout + stderr combined, for convenience. */
  out: string;
}

function withHome(fn: (home: string) => void): void {
  const home = mkdtempSync(path.join(os.tmpdir(), "mcpm-smoke-"));
  try {
    fn(home);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

function run(args: string[], home: string, extraEnv: NodeJS.ProcessEnv = {}): RunResult {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    encoding: "utf-8",
    timeout: 30_000,
    input: "", // empty stdin → a command that waits for a TTY prompt fails fast instead of hanging
    env: { ...process.env, HOME: home, MCPM_DISABLE_OS_KEYCHAIN: "1", ...extraEnv },
  });
  const stdout = r.stdout ?? "";
  const stderr = r.stderr ?? "";
  return { stdout, stderr, code: r.status ?? -1, out: `${stdout}\n${stderr}` };
}

describe("CLI smoke — verify lock coverage", () => {
  it.skipIf(process.platform === "win32").each([
    { name: "unrecorded", covered: false },
    { name: "constructor", covered: true },
  ])("propagates coverage for $name to the Action summary", ({ name, covered }) => {
    withHome((home) => {
      const stack = path.join(home, "mcpm.yaml");
      const endpoint = '{ url: "https://fixture.invalid/mcp" }';
      writeFileSync(stack, `version: "1"\nservers:\n  ${name}: ${endpoint}\n`);
      writeFileSync(
        path.join(home, "mcpm-lock.yaml"),
        `lockfileVersion: 1\nlockedAt: "2026-11-20"\nservers:\n  ${covered ? name : "other"}: ${endpoint}\n`,
      );

      const cli = run(["verify", "--file", stack, "--json"], home);
      const exitCode = covered ? 0 : 1;
      expect(cli.code).toBe(exitCode);
      expect(JSON.parse(cli.stdout)).toMatchObject({
        schemaVersion: 1,
        ok: covered,
        uncovered: covered ? [] : [name],
      });

      const action = parseYaml(readFileSync(".github/actions/mcpm-verify/action.yml", "utf8"));
      const summaryPath = path.join(home, "summary.md");
      // Execute the real composite step against the built CLI without downloading a package.
      const step = spawnSync("bash", ["-c", [
        'npx() { shift 2; "$MCPM_NODE" "$MCPM_BIN" "$@"; }',
        action.runs.steps[0].run,
      ].join("\n")], {
        cwd: home,
        encoding: "utf8",
        timeout: 30_000,
        env: {
          ...process.env,
          HOME: home,
          MCPM_DISABLE_OS_KEYCHAIN: "1",
          MCPM_CLI_VERSION: "local",
          MCPM_NODE: process.execPath,
          MCPM_BIN: BIN,
          GITHUB_STEP_SUMMARY: summaryPath,
        },
      });
      expect(step.status).toBe(exitCode);
      expect(JSON.parse(step.stdout)).toEqual(JSON.parse(cli.stdout));
      const summary = readFileSync(summaryPath, "utf8");
      expect(summary).toContain("### mcpm verify");
      if (covered) {
        expect(summary).not.toContain("missing from the lock");
      } else {
        expect(summary).toContain("1 declared server(s) missing from the lock");
        expect(summary).toContain(`- \`${name}\``);
      }
    });
  });
});

describe("CLI smoke — read-only client coverage", () => {
  function setup(home: string): string {
    const stack = path.join(home, "mcpm.yaml");
    writeFileSync(stack, 'version: "1"\nservers:\n  missing: { url: "https://missing.invalid/mcp" }\n');
    writeFileSync(path.join(home, "mcpm-lock.yaml"), 'lockfileVersion: 1\nlockedAt: "2026-11-20"\nservers:\n  missing: { url: "https://missing.invalid/mcp" }\n');
    mkdirSync(path.join(home, ".cursor"));
    writeFileSync(path.join(home, ".cursor", "mcp.json"), JSON.stringify({
      mcpServers: { present: { url: "https://present.invalid/mcp" } },
    }));
    return stack;
  }

  it("treats an absent client source as missing rather than unreadable", () => {
    withHome((home) => {
      const stack = setup(home);
      const sync = run(["sync", "--check", "--json"], home);
      expect(sync.code).toBe(0);
      expect(JSON.parse(sync.stdout).unreadableClients).toEqual([]);
      const diff = run(["diff", "--file", stack, "--json"], home);
      expect(diff.code).toBe(0);
      expect(JSON.parse(diff.stdout)).toContainEqual(expect.objectContaining({ name: "missing", status: "missing" }));
      const list = run(["list", "--json"], home);
      expect(list.code).toBe(0);
      expect(list.stderr).toBe("");
      expect(JSON.parse(list.stdout)).toHaveLength(1);
    });
  });

  function expectUnreadable(home: string, stack: string, client: string, readableClient: string): void {
    const sync = run(["sync", "--check", "--json"], home);
    expect(sync.code).toBe(2);
    expect(JSON.parse(sync.stdout).unreadableClients).toEqual([client]);
    const list = run(["list", "--json"], home);
    expect(list.code).toBe(0);
    expect(list.stderr).toContain(client);
    expect(JSON.parse(list.stdout)).toMatchObject([{ client: readableClient, serverName: "present" }]);
    const diff = run(["diff", "--file", stack, "--json"], home);
    expect(diff.code).toBe(0);
    expect(diff.stderr).toContain(client);
    expect(JSON.parse(diff.stdout)).toContainEqual(expect.objectContaining({
      name: "missing", status: "unreadable", clients: [client],
    }));
    expect(JSON.parse(diff.stdout)).not.toContainEqual(expect.objectContaining({ name: "missing", status: "missing" }));
  }

  it("preserves readable siblings when a client config is malformed", () => {
    withHome((home) => {
      const stack = setup(home);
      writeFileSync(path.join(home, ".claude.json"), "{broken");
      expectUnreadable(home, stack, "claude-code", "cursor");
    });
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "reports a client config behind a permission-denied directory",
    () => {
      withHome((home) => {
        const stack = setup(home);
        writeFileSync(path.join(home, ".claude.json"), JSON.stringify({
          mcpServers: { present: { type: "http", url: "https://present.invalid/mcp" } },
        }));
        const denied = path.join(home, ".cursor");
        chmodSync(denied, 0o000);
        try {
          expectUnreadable(home, stack, "cursor", "claude-code");
        } finally {
          chmodSync(denied, 0o700);
        }
      });
    },
  );
});

describe("CLI smoke — empty update queries", () => {
  it.each(["update", "outdated"])("%s keeps empty JSON and human output distinct", (command) => {
    withHome((home) => {
      const json = run([command, "--json"], home);
      expect(json.code).toBe(0);
      expect(JSON.parse(json.stdout)).toEqual([]);

      const plain = run([command], home);
      expect(plain.code).toBe(0);
      expect(plain.stdout.trim()).toBe("No servers installed.");
    });
  });
});

describe("CLI smoke — sanity", () => {
  it("--version prints the package version and exits 0", () => {
    withHome((home) => {
      const r = run(["--version"], home);
      expect(r.code).toBe(0);
      expect(r.stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
    });
  });
});

describe("CLI smoke — no-op paths must not claim false success", () => {
  it("guard reset-integrity with no pins.json says 'nothing to refresh' (not 'refreshed')", () => {
    withHome((home) => {
      const r = run(["guard", "reset-integrity", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/nothing to refresh/i);
      expect(r.out).not.toMatch(/integrity refreshed/i);
    });
  });

  it("guard reset-integrity WITH a pins.json still says 'refreshed' (positive control)", () => {
    withHome((home) => {
      mkdirSync(path.join(home, ".mcpm"), { recursive: true });
      writeFileSync(path.join(home, ".mcpm", "pins.json"), '{"format_version":1,"servers":{}}');
      const r = run(["guard", "reset-integrity", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/integrity refreshed/i);
    });
  });

  it("guard accept-drift for an unknown server says 'nothing to re-pin' (not 're-pinned')", () => {
    withHome((home) => {
      const hash = `sha256:${"0".repeat(64)}`;
      const r = run(["guard", "accept-drift", "ghost-server", "--new-hash", hash, "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/no existing pin.*nothing to re-pin/i);
      expect(r.out).not.toMatch(/re-pinned to/i);
    });
  });

  it("guard accept-drift --remove for an unknown server says 'nothing to remove'", () => {
    withHome((home) => {
      const r = run(["guard", "accept-drift", "ghost-server", "--remove", "--yes"], home);
      expect(r.code).toBe(0);
      expect(r.out).toMatch(/no existing pin.*nothing to remove/i);
    });
  });

  it("secrets rm of a never-stored secret errors (not a false 'Removed secret') and exits non-zero", () => {
    withHome((home) => {
      const r = run(["secrets", "rm", "ghost", "NEVERSET", "-y"], home);
      expect(r.code).not.toBe(0);
      expect(r.out).toMatch(/no secret stored/i);
      expect(r.out).not.toMatch(/removed secret/i);
    });
  });
});

describe("CLI smoke — CI-gate exit codes (docs/CONTRACTS.md)", () => {
  it("sync --check exits 2 when clients disagree (the drift signal CI consumes)", () => {
    withHome((home) => {
      mkdirSync(path.join(home, ".cursor"), { recursive: true });
      mkdirSync(path.join(home, ".codeium", "windsurf"), { recursive: true });
      // cursor has `foo`; windsurf does not -> drift.
      writeFileSync(
        path.join(home, ".cursor", "mcp.json"),
        '{"mcpServers":{"foo":{"command":"echo","args":["a"]}}}',
      );
      writeFileSync(path.join(home, ".codeium", "windsurf", "mcp_config.json"), '{"mcpServers":{}}');
      const r = run(["sync", "--check"], home);
      expect(r.code).toBe(2);
      expect(r.out).toMatch(/foo/);
    });
  });

  it("sync --check exits 0 with no client configs (no false drift)", () => {
    withHome((home) => {
      const r = run(["sync", "--check"], home);
      expect(r.code).toBe(0);
    });
  });

  it("up --frozen exits 1 when the stack file is missing (fail-closed, not a false pass)", () => {
    withHome((home) => {
      const r = run(["up", "--frozen"], home);
      expect(r.code).toBe(1);
      expect(r.out).toMatch(/stack file not found/i);
    });
  });

  // audit exit 2 = "this invocation cannot be satisfied", distinct from exit 1 = "a
  // server is risky". Only the built binary exercises it: the mapping lives in the
  // Commander action's catch, which the handler-level tests bypass entirely — without
  // these, replacing the ternary with `return 1` leaves the whole suite green.
  it.each([
    [["audit", "--sarif", "--fix"], /--sarif is report-only/i],
    [["audit", "--min-trust", "50"], /--min-trust requires --fix/i],
    [["audit", "--fix", "--json"], /requires --yes/i],
  ])("audit %s exits 2 (invocation cannot be satisfied)", (argv, pattern) => {
    withHome((home) => {
      const r = run(argv as string[], home);
      expect(r.code).toBe(2);
      expect(r.out).toMatch(pattern);
    });
  });

  it("audit exits 1, not 2, on a Commander argument-parse failure", () => {
    // The scoped half of the CONTRACTS promise: exit 2 covers the invocations mcpm
    // itself refuses, NOT everything a user can mistype. parseMinTrust raises
    // Commander's InvalidArgumentError, which never reaches audit's catch.
    withHome((home) => {
      const r = run(["audit", "--fix", "--min-trust", "150"], home);
      expect(r.code).toBe(1);
    });
  });

  it("audit exits 0 on a clean run with no servers installed", () => {
    withHome((home) => {
      const r = run(["audit"], home);
      expect(r.code).toBe(0);
    });
  });

  // #118: only the built binary sees `process.exitCode` — the wiring lives in the
  // Commander action, which the handler-level tests bypass. A client config that
  // cannot be parsed must stop `cleanup --yes` from erasing that client's pins.
  it("guard cleanup --yes refuses (exit 1, pins untouched) when a client config is unreadable, and prunes once it is fixed", () => {
    withHome((home) => {
      const pin = (c: string) => ({
        current_hash: `sha256:${c.repeat(64)}`,
        previous_hashes: [],
        captured_at: "x",
        captured_via: "first-session",
        signature_list_version: "v0.5.0",
      });
      mkdirSync(path.join(home, ".mcpm"), { recursive: true });
      mkdirSync(path.join(home, ".gemini"), { recursive: true });
      const pinsPath = path.join(home, ".mcpm", "pins.json");
      writeFileSync(path.join(home, ".claude.json"), '{"mcpServers":{"a":{"command":"node","args":["a.js"]}}}');
      writeFileSync(path.join(home, ".gemini", "settings.json"), '{"mcpServers":{"b":{"command":"node"},}}');
      writeFileSync(
        pinsPath,
        JSON.stringify({ format_version: 1, servers: { a: { tool: pin("a") }, b: { tool: pin("b") } } }),
      );
      expect(run(["guard", "reset-integrity", "--yes"], home).code).toBe(0);
      const before = readFileSync(pinsPath, "utf-8");

      const refused = run(["guard", "cleanup", "--yes"], home);
      expect(refused.code).toBe(1);
      expect(refused.out).toMatch(/gemini-cli/);
      expect(refused.out).toMatch(/refusing to prune/i);
      expect(refused.out).not.toMatch(/pruned/i);
      expect(readFileSync(pinsPath, "utf-8")).toBe(before);

      // Positive control: same pins, Gemini config now readable and without `b`.
      writeFileSync(path.join(home, ".gemini", "settings.json"), '{"mcpServers":{}}');
      const pruned = run(["guard", "cleanup", "--yes"], home);
      expect(pruned.code).toBe(0);
      expect(pruned.out).toMatch(/pruned 1 orphan pin entry/i);
    });
  });
});

describe("CLI smoke — guard list-signatures carries the OWASP MCP Top 10 pin (backlog #71)", () => {
  it("--json emits an owasp object per signature", () => {
    withHome((home) => {
      const r = run(["guard", "list-signatures", "--json"], home);
      expect(r.code).toBe(0);
      const sigs = JSON.parse(r.stdout) as Array<{ id: string; owasp: { status: string } }>;
      expect(sigs.length).toBeGreaterThan(0);
      const pinned = sigs.find((s) => s.id === "owasp-mcp-1-tool-description-injection");
      expect(pinned?.owasp).toEqual({
        status: "pinned",
        id: "MCP03",
        ref: "165fe0f78ef104459237b4a8e0f6e78db9b02391",
      });
      const unpinnable = sigs.find((s) => s.id === "guard-inspection-truncated");
      expect(unpinnable?.owasp.status).toBe("unpinnable");
    });
  });

  it("text output prints an owasp line naming the pinned category", () => {
    withHome((home) => {
      const r = run(["guard", "list-signatures"], home);
      expect(r.code).toBe(0);
      expect(r.stdout).toMatch(/owasp\s*: MCP03 @ 165fe0f7/);
    });
  });
});

describe("CLI smoke — generated completions", () => {
  it("uses the init help description in zsh and fish completions", () => {
    withHome((home) => {
      const help = run(["init", "--help"], home);
      expect(help.code).toBe(0);
      const description = help.stdout.split(/\r?\n/).find((line) => line.startsWith("Scaffold a starter"));
      expect(description).toBeDefined();

      const zsh = run(["completions", "zsh"], home);
      expect(zsh.code).toBe(0);
      expect(zsh.stdout).toContain(`'init:${description}'`);

      const fish = run(["completions", "fish"], home);
      expect(fish.code).toBe(0);
      expect(fish.stdout).toContain(`-a init -d '${description}'`);
    });
  });

  it("the bash completion script passes `bash -n` (syntax check)", () => {
    withHome((home) => {
      const script = run(["completions", "bash"], home).stdout;
      expect(script.length).toBeGreaterThan(0);
      const check = spawnSync("bash", ["-n"], { input: script, encoding: "utf-8", timeout: 10_000 });
      if (check.error && (check.error as NodeJS.ErrnoException).code === "ENOENT") return; // bash absent — skip
      expect(check.status, `bash -n rejected the script:\n${check.stderr}`).toBe(0);
    });
  });
});

describe("CLI smoke — Codex scope inventory", () => {
  function fixture(fn: (root: string, home: string, project: string, user: string) => void) {
    withHome((temporary) => {
      const root = path.join(realpathSync(temporary), "repo");
      const home = path.join(realpathSync(temporary), "home");
      const project = path.join(root, ".codex", "config.toml");
      const user = path.join(home, "config.toml");
      mkdirSync(path.dirname(project), { recursive: true });
      mkdirSync(home);
      fn(root, home, project, user);
    });
  }

  function inventory(root: string, codexHome: string, json = true) {
    const args = ["scope", root, "--client", "codex"];
    if (json) args.push("--json");
    return run(args, path.dirname(root), { CODEX_HOME: codexHome, USERPROFILE: path.dirname(root) });
  }

  it("reports both origins and declared restrictions without exposing launch values", () => {
    fixture((root, home, project, user) => {
      writeFileSync(project, `
[mcp_servers.overlap]
command = "fixture-secret-command"
args = ["fixture-secret-arg"]
env = { API_KEY = "fixture-secret-env" }
enabled_tools = ["project_tool"]
[mcp_servers.disabled_fixture]
url = "https://fixture-secret.invalid/mcp"
http_headers = { Authorization = "fixture-secret-header" }
bearer_token_env_var = "fixture-secret-token-ref"
enabled = false
disabled_tools = ["blocked_tool"]
`);
      writeFileSync(user, `
[mcp_servers.overlap]
command = "fixture-secret-user-command"
enabled = true
enabled_tools = ["user_tool"]
disabled_tools = []
`);
      // A populated fallback must not be consulted when CODEX_HOME is explicit.
      const fallback = path.join(path.dirname(root), ".codex");
      mkdirSync(fallback);
      writeFileSync(path.join(fallback, "config.toml"), "[mcp_servers.fallback_only]");
      writeFileSync(path.join(root, ".mcp.json"), '{"mcpServers":{"other_host":{}}}');
      const result = inventory(root, home);
      expect(result.code).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({
        client: "codex", schemaVersion: 1, inventoryComplete: true, trust: "unknown",
        effective: "unknown", loaded: "unknown", enforced: "unknown", instructions: [],
        sources: [
          { origin: "codex-project", path: project, state: "present" },
          { origin: "codex-user", path: user, state: "present" },
        ],
        servers: [
          { name: "disabled_fixture", origin: "codex-project", enabled: false, enabledTools: null,
            disabledTools: ["blocked_tool"], sameNameIn: [] },
          { name: "overlap", origin: "codex-project", enabled: null, enabledTools: ["project_tool"],
            sameNameIn: ["codex-user"] },
          { name: "overlap", origin: "codex-user", enabled: true, enabledTools: ["user_tool"],
            disabledTools: [], sameNameIn: ["codex-project"] },
        ],
      });
      const human = inventory(root, home, false);
      expect(human.code).toBe(0);
      expect(human.stdout).toContain("blocked_tool");
      expect(human.stdout).toContain("same name in: codex-user");
      expect(result.out + human.out).not.toMatch(/fixture-secret|fallback_only|other_host/);
    });
  });

  it("uses the default Codex home when no explicit path is supplied", () => {
    fixture((root) => {
      const home = path.join(path.dirname(root), ".codex");
      mkdirSync(home);
      const user = path.join(home, "config.toml");
      writeFileSync(user, '[mcp_servers.user_only]\ncommand = "fixture-secret"');
      const result = inventory(root, "");
      expect(result.code).toBe(0);
      expect(JSON.parse(result.stdout)).toMatchObject({
        inventoryComplete: true,
        sources: [{ state: "missing" }, { path: user, state: "present" }],
        servers: [{ name: "user_only", origin: "codex-user" }],
      });
      expect(result.out).not.toContain("fixture-secret");
    });
  });

  it.each([
    { label: "invalid syntax", data: '[mcp_servers.bad\ncommand = "fixture-secret"' },
    { label: "duplicate keys", data: '[mcp_servers.bad]\nenabled = true\nenabled = false' },
    { label: "invalid UTF-8", data: Buffer.from([0xc0, 0x80]) },
    { label: "oversized input", data: Buffer.alloc(1024 * 1024 + 1, 0x20), state: "too-large" },
  ])("keeps the readable sibling with $label", ({ data, state }) => {
    fixture((root, home, project, user) => {
      writeFileSync(project, data);
      writeFileSync(user, '[mcp_servers.readable]\nenabled_tools = ["kept"]');
      const result = inventory(root, home);
      expect(result.code).toBe(1);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({
        inventoryComplete: false,
        sources: [{ state: state ?? "malformed" }, { state: "present" }],
        servers: [{ name: "readable", enabledTools: ["kept"] }],
      });
      expect(result.out).not.toContain("fixture-secret");
    });
  });

  it("retains valid declarations in a source with malformed reported metadata", () => {
    fixture((root, home, project) => {
      writeFileSync(project, '[mcp_servers.bad]\nenabled = "fixture-secret"\nenabled_tools = [42]\n[mcp_servers.good]\nenabled = true');
      const result = inventory(root, home);
      expect(result.code).toBe(1);
      expect(JSON.parse(result.stdout)).toMatchObject({
        sources: [{ state: "malformed" }, { state: "missing" }],
        servers: [
          { name: "bad", declaration: "malformed", enabled: null, enabledTools: null },
          { name: "good", declaration: "object", enabled: true },
        ],
      });
      expect(result.out).not.toContain("fixture-secret");
    });
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "retains a readable sibling when the project config cannot be read",
    () => fixture((root, home, project, user) => {
      writeFileSync(project, "[mcp_servers.protected]");
      writeFileSync(user, "[mcp_servers.readable]");
      chmodSync(project, 0o000);
      try {
        const result = inventory(root, home);
        expect(result.code).toBe(1);
        expect(JSON.parse(result.stdout)).toMatchObject({
          sources: [{ state: "unreadable" }, { state: "present" }],
          servers: [{ name: "readable" }],
        });
        expect(result.out).not.toContain("protected");
      } finally {
        chmodSync(project, 0o600);
      }
    })
  );

  it.skipIf(process.platform === "win32")("skips symlinked files and home components", () => {
    fixture((root, home, project, user) => {
      writeFileSync(user, "[mcp_servers.readable]");
      symlinkSync(user, project);
      const linkedHome = path.join(path.dirname(root), "linked-home");
      symlinkSync(home, linkedHome);
      for (const [selected, state] of [[home, "present"], [linkedHome, "symlink-skipped"]]) {
        const result = inventory(root, selected);
        expect(result.code).toBe(1);
        const report = JSON.parse(result.stdout);
        expect(report.sources.map((source: { state: string }) => source.state)).toEqual(["symlink-skipped", state]);
        expect(report.servers.map((server: { origin: string }) => server.origin)).toEqual(
          selected === home ? ["codex-user"] : []
        );
      }
    });
  });
});
