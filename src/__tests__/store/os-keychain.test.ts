/**
 * Tests for src/store/os-keychain.ts — zero-native-dep OS credential store
 * access (security #15). The platform tools are never run for real: we mock
 * node:child_process `spawn` and script per-call exit codes / stdout.
 *
 * Strategy: a tiny fake child process (custom emitter) lets `run()` attach its
 * listeners synchronously; the scripted result is emitted on the next
 * microtask. `h.calls` records command/args/stdin so we can assert the exact
 * invocation shape on each platform.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const h = vi.hoisted(() => ({
  scripted: [] as Array<{ stdout?: string; stderr?: string; code: number | null }>,
  calls: [] as Array<{ command: string; args: string[]; input?: string; env?: NodeJS.ProcessEnv }>,
}));

vi.mock("node:child_process", () => {
  function emitter() {
    const map: Record<string, Array<(...a: unknown[]) => void>> = {};
    return {
      on(ev: string, cb: (...a: unknown[]) => void) {
        (map[ev] ??= []).push(cb);
        return this;
      },
      emit(ev: string, ...a: unknown[]) {
        (map[ev] ?? []).forEach((f) => f(...a));
      },
    };
  }
  return {
    spawn(command: string, args: string[], opts: { env?: NodeJS.ProcessEnv }) {
      const next = h.scripted.shift() ?? { code: 0, stdout: "" };
      const call: (typeof h.calls)[number] = { command, args, env: opts?.env };
      h.calls.push(call);
      const child = emitter() as ReturnType<typeof emitter> & {
        stdout: ReturnType<typeof emitter>;
        stderr: ReturnType<typeof emitter>;
        stdin: { on: () => void; end: (input?: string) => void };
      };
      child.stdout = emitter();
      child.stderr = emitter();
      child.stdin = {
        on: () => {},
        end: (input?: string) => {
          call.input = input;
        },
      };
      queueMicrotask(() => {
        if (next.stdout) child.stdout.emit("data", Buffer.from(next.stdout));
        if (next.stderr) child.stderr.emit("data", Buffer.from(next.stderr));
        if (next.code === null) child.emit("error", new Error("spawn ENOENT"));
        else child.emit("close", next.code);
      });
      return child;
    },
  };
});

// Windows path touches the filesystem + store dir — mock both so no real IO.
vi.mock("../../store/index.js", () => ({
  getStorePath: vi.fn(async () => "/fake/.mcpm"),
}));
const fsMocks = vi.hoisted(() => ({ readFile: vi.fn(), writeFile: vi.fn() }));
vi.mock("node:fs/promises", () => fsMocks);

const ORIG_PLATFORM = process.platform;
function setPlatform(p: NodeJS.Platform): void {
  Object.defineProperty(process, "platform", { value: p, configurable: true });
}

const KEY = Buffer.alloc(32, 7);
const KEY_B64 = KEY.toString("base64");

beforeEach(() => {
  h.scripted.length = 0;
  h.calls.length = 0;
  fsMocks.readFile.mockReset();
  fsMocks.writeFile.mockReset();
  delete process.env.MCPM_DISABLE_OS_KEYCHAIN; // setupFiles defaults this to "1"
});

afterEach(() => {
  setPlatform(ORIG_PLATFORM);
});

describe("isSupportedPlatform", () => {
  it("is true on darwin/linux/win32 and false elsewhere", async () => {
    const { isSupportedPlatform } = await import("../../store/os-keychain.js");
    for (const p of ["darwin", "linux", "win32"] as const) {
      setPlatform(p);
      expect(isSupportedPlatform()).toBe(true);
    }
    setPlatform("aix" as NodeJS.Platform);
    expect(isSupportedPlatform()).toBe(false);
  });

  it("is false when MCPM_DISABLE_OS_KEYCHAIN=1", async () => {
    const { isSupportedPlatform } = await import("../../store/os-keychain.js");
    setPlatform("darwin");
    process.env.MCPM_DISABLE_OS_KEYCHAIN = "1";
    expect(isSupportedPlatform()).toBe(false);
  });
});

describe("macOS (security)", () => {
  beforeEach(() => setPlatform("darwin"));

  it("getStoredKey reads a 32-byte key from find-generic-password", async () => {
    h.scripted.push({ code: 0, stdout: `${KEY_B64}\n` });
    const { getStoredKey } = await import("../../store/os-keychain.js");
    const got = await getStoredKey();
    expect(got).not.toBeNull();
    expect(got!.equals(KEY)).toBe(true);
    expect(h.calls[0].command).toBe("security");
    expect(h.calls[0].args).toEqual(
      expect.arrayContaining(["find-generic-password", "-s", "mcpm", "-w"])
    );
  });

  it("getStoredKey returns null when the item is absent (exit 44)", async () => {
    h.scripted.push({ code: 44, stderr: "could not be found" });
    const { getStoredKey } = await import("../../store/os-keychain.js");
    expect(await getStoredKey()).toBeNull();
  });

  it("storeKey calls add-generic-password with -U and returns true", async () => {
    h.scripted.push({ code: 0 });
    const { storeKey } = await import("../../store/os-keychain.js");
    expect(await storeKey(KEY)).toBe(true);
    expect(h.calls[0].args).toEqual(
      expect.arrayContaining(["add-generic-password", "-U", "-w", KEY_B64])
    );
  });
});

describe("Linux (secret-tool)", () => {
  beforeEach(() => setPlatform("linux"));

  it("getStoredKey reads the key via lookup", async () => {
    h.scripted.push({ code: 0, stdout: KEY_B64 });
    const { getStoredKey } = await import("../../store/os-keychain.js");
    expect((await getStoredKey())!.equals(KEY)).toBe(true);
    expect(h.calls[0].command).toBe("secret-tool");
    expect(h.calls[0].args[0]).toBe("lookup");
  });

  it("storeKey passes the key on stdin, not argv", async () => {
    h.scripted.push({ code: 0 });
    const { storeKey } = await import("../../store/os-keychain.js");
    expect(await storeKey(KEY)).toBe(true);
    expect(h.calls[0].args[0]).toBe("store");
    expect(h.calls[0].args).not.toContain(KEY_B64); // never on the command line
    expect(h.calls[0].input).toBe(KEY_B64); // delivered via stdin
  });

  it("returns null/false when secret-tool is missing (spawn error)", async () => {
    h.scripted.push({ code: null });
    const osk = await import("../../store/os-keychain.js");
    expect(await osk.getStoredKey()).toBeNull();
    h.scripted.push({ code: null });
    expect(await osk.storeKey(KEY)).toBe(false);
  });
});

describe("Windows (DPAPI via PowerShell)", () => {
  beforeEach(() => setPlatform("win32"));

  it("storeKey protects the key (env, not argv) and writes the blob 0600", async () => {
    h.scripted.push({ code: 0, stdout: "PROTECTED_BLOB_B64" });
    const { storeKey } = await import("../../store/os-keychain.js");
    expect(await storeKey(KEY)).toBe(true);
    expect(h.calls[0].command).toBe("powershell");
    expect(h.calls[0].args).not.toContain(KEY_B64);
    expect(h.calls[0].env?.MCPM_KEY_B64).toBe(KEY_B64);
    expect(fsMocks.writeFile).toHaveBeenCalledWith(
      "/fake/.mcpm/master-key.dpapi",
      "PROTECTED_BLOB_B64",
      { mode: 0o600 }
    );
  });

  it("getStoredKey unprotects the stored blob", async () => {
    fsMocks.readFile.mockResolvedValue("STORED_BLOB\n");
    h.scripted.push({ code: 0, stdout: KEY_B64 });
    const { getStoredKey } = await import("../../store/os-keychain.js");
    expect((await getStoredKey())!.equals(KEY)).toBe(true);
    expect(h.calls[0].env?.MCPM_BLOB_B64).toBe("STORED_BLOB");
  });

  it("getStoredKey returns null when no blob file exists", async () => {
    fsMocks.readFile.mockRejectedValue(Object.assign(new Error("nope"), { code: "ENOENT" }));
    const { getStoredKey } = await import("../../store/os-keychain.js");
    expect(await getStoredKey()).toBeNull();
  });
});

describe("key validation", () => {
  beforeEach(() => setPlatform("darwin"));

  it("rejects a stored value that is not exactly 32 bytes", async () => {
    h.scripted.push({ code: 0, stdout: Buffer.alloc(16, 1).toString("base64") });
    const { getStoredKey } = await import("../../store/os-keychain.js");
    expect(await getStoredKey()).toBeNull();
  });

  it("storeKey refuses a key that is not 32 bytes (no spawn)", async () => {
    const { storeKey } = await import("../../store/os-keychain.js");
    expect(await storeKey(Buffer.alloc(16))).toBe(false);
    expect(h.calls.length).toBe(0);
  });
});
