/**
 * #65 — a server entry legitimately named `__proto__` was invisible everywhere.
 *
 * `read()` accumulated into an object LITERAL and wrote with plain assignment
 * (`out[name] = parsed.data`), so the name `__proto__` hit `Object.prototype`'s
 * inherited setter instead of creating an own property. Two consequences, both
 * silent:
 *
 *   1. The entry never appears in `Object.entries(out)` — it vanishes from
 *      `list`, `export`, `sync`, `diff` and the drift model — and `onSkip`
 *      never fires, because the entry is not malformed. A security tool that
 *      cannot see a configured server cannot audit, guard or remove it.
 *   2. Worse: the map's PROTOTYPE becomes the attacker-supplied entry, so
 *      `"command" in servers` is true and `servers.command` returns the
 *      entry's command string typed as an `McpServerEntry`.
 *
 * Client config is untrusted input (CLAUDE.md's own threat model — OX Security's
 * config-`command`-to-spawn class, Claude Code CVE-2025-59536), and every client
 * mcpm writes for iterates its own config with `Object.entries`, so such a
 * server DOES launch. mcpm must see what the client sees.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  rename: vi.fn(),
  mkdir: vi.fn(),
  lstat: vi.fn(),
  unlink: vi.fn(),
}));

import { readFile, lstat } from "fs/promises";
import { ClaudeDesktopAdapter } from "../../../config/adapters/claude-desktop.js";

const mockReadFile = readFile as ReturnType<typeof vi.fn>;
const mockLstat = lstat as ReturnType<typeof vi.fn>;

const CONFIG_PATH = "/fake/claude_desktop_config.json";
const PROTO_ENTRY = { command: "evil", args: ["-y", "payload"], env: { K: "v" } };

// The fixtures are RAW JSON text on purpose. Building them with an object
// literal (`{ __proto__: PROTO_ENTRY }`) walks into the very trap under test:
// the literal sets the object's PROTOTYPE, `JSON.stringify` then emits `{}`,
// and the test passes against unmodified code while exercising nothing.
const PROTO_JSON = '{"command":"evil","args":["-y","payload"],"env":{"K":"v"}}';
const withProto = (extra = "") =>
  `{"mcpServers":{${extra}"__proto__":${PROTO_JSON}}}`;

describe("BaseAdapter.read() — an entry named __proto__ (#65)", () => {
  const adapter = new ClaudeDesktopAdapter();
  let onSkip: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.resetAllMocks();
    mockLstat.mockResolvedValue({ isSymbolicLink: () => false });
    onSkip = vi.fn();
    vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  it("returns it as an own enumerable entry alongside its siblings", async () => {
    mockReadFile.mockResolvedValue(
      withProto('"good":{"command":"npx","args":["-y","server"]},'),
    );

    const result = await adapter.read(CONFIG_PATH, onSkip);

    expect(Object.keys(result).sort()).toEqual(["__proto__", "good"]);
    expect(Object.entries(result).map(([n]) => n).sort()).toEqual(["__proto__", "good"]);
    expect(result["__proto__"]).toEqual(PROTO_ENTRY);
    // It is well-formed: it must NOT be reported as skipped.
    expect(onSkip).not.toHaveBeenCalled();
  });

  it("does not let the entry become the map's prototype", async () => {
    mockReadFile.mockResolvedValue(withProto());

    const result = await adapter.read(CONFIG_PATH, onSkip);

    expect(Object.getPrototypeOf(result)).not.toBe(PROTO_ENTRY);
    // A lookup for a name that collides with an entry FIELD must miss, not
    // return the attacker's value typed as an McpServerEntry.
    expect("command" in result).toBe(false);
    expect((result as Record<string, unknown>)["command"]).toBeUndefined();
  });

  it("survives the JSON round-trip clients themselves perform", async () => {
    mockReadFile.mockResolvedValue(withProto());

    const result = await adapter.read(CONFIG_PATH, onSkip);

    expect(JSON.stringify(result)).toBe(`{"__proto__":${PROTO_JSON}}`);
  });
});
