import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  StackFileSchema,
  LockFileSchema,
  parseStackFile,
  parseLockFile,
  serializeYaml,
  isRegistryServer,
  isUrlServer,
} from "../../stack/schema.js";
import type { StackFile } from "../../stack/schema.js";
import { parse as parseYaml } from "yaml";
import { writeFile, mkdtemp } from "fs/promises";
import path from "path";
import os from "os";

// ---------------------------------------------------------------------------
// StackFileSchema validation
// ---------------------------------------------------------------------------

describe("StackFileSchema", () => {
  it("accepts a valid stack file with version entries", () => {
    const input = {
      version: "1",
      servers: {
        "io.github.domdomegg/filesystem-mcp": {
          version: "^1.0.0",
          profiles: ["dev", "prod"],
        },
      },
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it("accepts a valid stack file with url entries", () => {
    const input = {
      version: "1",
      servers: {
        "my-internal-server": {
          url: "https://internal.company.com/mcp",
        },
      },
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it("rejects unsupported version", () => {
    const input = {
      version: "2",
      servers: {},
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0].message).toContain("Unsupported stack file version");
    }
  });

  it("validates policy.minTrustScore range (0-100)", () => {
    const valid = {
      version: "1",
      policy: { minTrustScore: 60 },
      servers: {},
    };
    expect(StackFileSchema.safeParse(valid).success).toBe(true);

    const tooHigh = {
      version: "1",
      policy: { minTrustScore: 101 },
      servers: {},
    };
    expect(StackFileSchema.safeParse(tooHigh).success).toBe(false);

    const tooLow = {
      version: "1",
      policy: { minTrustScore: -1 },
      servers: {},
    };
    expect(StackFileSchema.safeParse(tooLow).success).toBe(false);
  });

  it("validates profiles array on server entries", () => {
    const input = {
      version: "1",
      servers: {
        "my-server": {
          version: "1.0.0",
          profiles: ["dev", "prod"],
        },
      },
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      const server = result.data.servers["my-server"];
      expect(isRegistryServer(server)).toBe(true);
      if (isRegistryServer(server)) {
        expect(server.profiles).toEqual(["dev", "prod"]);
      }
    }
  });

  it("rejects server entries with both version and url (mutual exclusion)", () => {
    const input = {
      version: "1",
      servers: {
        "bad-server": {
          version: "^1.0.0",
          url: "https://example.com/mcp",
        },
      },
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(false);
  });

  it("validates env declarations with secret, required, default", () => {
    const input = {
      version: "1",
      servers: {
        "my-server": {
          version: "1.0.0",
          env: {
            API_KEY: { required: true, secret: true },
            DB_PATH: { required: true, default: "./data/app.db" },
          },
        },
      },
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      const server = result.data.servers["my-server"];
      if (isRegistryServer(server)) {
        expect(server.env?.API_KEY.secret).toBe(true);
        expect(server.env?.DB_PATH.default).toBe("./data/app.db");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// PolicySchema — F4 keys (minReleaseAgeHours, blockInstallScripts)
// ---------------------------------------------------------------------------

describe("PolicySchema — F4 keys", () => {
  it("parseStackFile accepts and preserves minReleaseAgeHours and blockInstallScripts", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-schema-test-"));
    const filePath = path.join(dir, "mcpm.yaml");
    await writeFile(
      filePath,
      `
version: "1"
policy:
  minReleaseAgeHours: 24
  blockInstallScripts: true
servers: {}
`,
      "utf-8"
    );

    const stack = await parseStackFile(filePath);
    expect(stack.policy?.minReleaseAgeHours).toBe(24);
    expect(stack.policy?.blockInstallScripts).toBe(true);
  });

  it("rejects negative and non-integer minReleaseAgeHours", () => {
    const negative = {
      version: "1",
      policy: { minReleaseAgeHours: -1 },
      servers: {},
    };
    expect(StackFileSchema.safeParse(negative).success).toBe(false);

    const fractional = {
      version: "1",
      policy: { minReleaseAgeHours: 24.5 },
      servers: {},
    };
    expect(StackFileSchema.safeParse(fractional).success).toBe(false);
  });

  it("keeps backward compat and silently strips unknown policy keys (strip-mode footgun)", () => {
    // Pre-F4 stack files keep parsing.
    const preF4 = {
      version: "1",
      policy: { minTrustScore: 60, blockOnScoreDrop: true },
      servers: {},
    };
    expect(StackFileSchema.safeParse(preF4).success).toBe(true);

    // DOCUMENTED FOOTGUN: a typo'd key (minReleaseAgeHrs) parses fine and is
    // silently dropped — which disarms the gate. Pre-existing PolicySchema
    // strip-mode behavior; .strict() would break forward compat, so we pin the
    // behavior here instead of "fixing" it.
    const typoKey = {
      version: "1",
      policy: { minReleaseAgeHrs: 24 },
      servers: {},
    };
    const result = StackFileSchema.safeParse(typoKey);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.policy?.minReleaseAgeHours).toBeUndefined();
      expect(result.data.policy).not.toHaveProperty("minReleaseAgeHrs");
    }
  });

  it("leaves blockInstallScripts undefined when omitted (no default injection)", () => {
    const input = {
      version: "1",
      policy: { minTrustScore: 60 },
      servers: {},
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.policy?.blockInstallScripts).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// PolicySchema — H9 allowUrlServers (durable unguarded consent)
// ---------------------------------------------------------------------------

describe("PolicySchema — H9 allowUrlServers", () => {
  it("accepts and preserves policy.allowUrlServers: true", () => {
    const input = {
      version: "1",
      policy: { allowUrlServers: true },
      servers: {},
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.policy?.allowUrlServers).toBe(true);
    }
  });

  it("leaves allowUrlServers undefined when omitted (bare optional, no default)", () => {
    const input = {
      version: "1",
      policy: { minTrustScore: 60 },
      servers: {},
    };
    const result = StackFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.policy?.allowUrlServers).toBeUndefined();
    }
  });
});

// ---------------------------------------------------------------------------
// LockFileSchema validation
// ---------------------------------------------------------------------------

describe("LockFileSchema", () => {
  it("accepts a valid lock file", () => {
    const input = {
      lockfileVersion: 1,
      lockedAt: "2026-04-05T10:00:00Z",
      servers: {
        "io.github.domdomegg/filesystem-mcp": {
          version: "1.3.0",
          registryType: "npm",
          identifier: "filesystem-mcp",
          trust: {
            score: 82,
            maxPossible: 100,
            level: "safe",
            assessedAt: "2026-04-05T10:00:00Z",
          },
        },
      },
    };
    const result = LockFileSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it("accepts a lock file with url entries", () => {
    const input = {
      lockfileVersion: 1,
      lockedAt: "2026-04-05T10:00:00Z",
      servers: {
        "my-remote": {
          url: "https://example.com/mcp",
        },
      },
    };
    const result = LockFileSchema.safeParse(input);
    expect(result.success).toBe(true);
  });

  it("preserves externalScanCredit on the trust snapshot (#35)", () => {
    // The snapshot in "accepts a valid lock file" has no externalScanCredit and
    // still parses — that is the pre-#35 back-compat case. This asserts the field
    // round-trips when present, so the native-drop check can recover the baseline.
    const input = {
      lockfileVersion: 1,
      lockedAt: "2026-08-05T10:00:00Z",
      servers: {
        "io.github.example/scanned": {
          version: "1.0.0",
          registryType: "npm",
          identifier: "scanned",
          trust: {
            score: 82,
            maxPossible: 100,
            level: "safe",
            assessedAt: "2026-08-05T10:00:00Z",
            externalScanCredit: 18,
          },
        },
      },
    };
    const result = LockFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      const server = result.data.servers["io.github.example/scanned"];
      expect(server && "trust" in server && server.trust?.externalScanCredit).toBe(18);
    }
  });

  it("preserves dropCheckNativeScore on the trust snapshot (#41)", () => {
    // Same back-compat shape as #35: absent on old lockfiles (still parses),
    // round-trips when present.
    const input = {
      lockfileVersion: 1,
      lockedAt: "2026-08-05T10:00:00Z",
      servers: {
        "io.github.example/scanned": {
          version: "1.0.0",
          registryType: "npm",
          identifier: "scanned",
          trust: {
            score: 82,
            maxPossible: 100,
            level: "safe",
            assessedAt: "2026-08-05T10:00:00Z",
            externalScanCredit: 18,
            dropCheckNativeScore: 55,
          },
        },
      },
    };
    const result = LockFileSchema.safeParse(input);
    expect(result.success).toBe(true);
    if (result.success) {
      const server = result.data.servers["io.github.example/scanned"];
      expect(server && "trust" in server && server.trust?.dropCheckNativeScore).toBe(55);
    }
  });
});

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

describe("type guards", () => {
  it("isRegistryServer returns true for version entries", () => {
    expect(isRegistryServer({ version: "^1.0.0" })).toBe(true);
    expect(isRegistryServer({ url: "https://example.com" })).toBe(false);
  });

  it("isUrlServer returns true for url entries", () => {
    expect(isUrlServer({ url: "https://example.com" })).toBe(true);
    expect(isUrlServer({ version: "^1.0.0" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// parseStackFile
// ---------------------------------------------------------------------------

describe("parseStackFile", () => {
  it("throws with clear message when file not found", async () => {
    await expect(parseStackFile("/nonexistent/mcpm.yaml")).rejects.toThrow(
      "Stack file not found"
    );
  });
});

// ---------------------------------------------------------------------------
// parseLockFile
// ---------------------------------------------------------------------------

describe("parseLockFile", () => {
  it("returns null when lock file does not exist", async () => {
    const result = await parseLockFile("/nonexistent/mcpm-lock.yaml");
    expect(result).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// serializeStackFile round-trip
// ---------------------------------------------------------------------------

describe("serializeYaml", () => {
  it("produces valid YAML that round-trips through parse", () => {
    const stack: StackFile = {
      version: "1",
      servers: {
        "my-server": { version: "^1.0.0" },
      },
    };
    const yaml = serializeYaml(stack);
    const parsed = parseYaml(yaml);
    const result = StackFileSchema.safeParse(parsed);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.servers["my-server"]).toMatchObject({
        version: "^1.0.0",
      });
    }
  });
});

// ---------------------------------------------------------------------------
// #65 — a stack file declaring a server named `__proto__`
// ---------------------------------------------------------------------------

describe("parseStackFile — a server named __proto__ (#65)", () => {
  async function writeStack(body: string): Promise<string> {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-proto-stack-"));
    const filePath = path.join(dir, "mcpm.yaml");
    await writeFile(filePath, body, "utf-8");
    return filePath;
  }

  it("refuses the file instead of silently parsing one server short", async () => {
    // `z.record` DISCARDS this key, so without the guard the parse succeeds
    // with 1 of the 2 declared servers and `lock` / `up --frozen` / `verify`
    // all enforce against less than the file says — the exact failure lock.ts
    // already refuses to WRITE a lock for.
    const filePath = await writeStack(
      `version: "1"\nservers:\n  __proto__:\n    version: "1.0.0"\n  good:\n    version: "2.0.0"\n`
    );

    await expect(parseStackFile(filePath)).rejects.toThrow(/__proto__/);
    await expect(parseStackFile(filePath)).rejects.toThrow(/cannot be represented/);
  });

  it("refuses it even when it is the only server", async () => {
    const filePath = await writeStack(
      `version: "1"\nservers:\n  __proto__:\n    version: "1.0.0"\n`
    );
    await expect(parseStackFile(filePath)).rejects.toThrow(/cannot be represented/);
  });

  it("still accepts the names z.record does NOT drop", async () => {
    // Measured: `__proto__` is the only key discarded. Refusing the others
    // would reject stacks that round-trip perfectly well.
    const filePath = await writeStack(
      `version: "1"\nservers:\n  constructor:\n    version: "1.0.0"\n` +
        `  prototype:\n    version: "1.0.0"\n  toString:\n    version: "1.0.0"\n`
    );

    const stack = await parseStackFile(filePath);
    expect(Object.keys(stack.servers).sort()).toEqual([
      "constructor",
      "prototype",
      "toString",
    ]);
  });

  it("leaves a malformed `servers` to Zod instead of crashing on it", async () => {
    // Pins the nullish clause. Without it `Object.hasOwn(null, ...)` throws a
    // raw TypeError and the user loses Zod's readable diagnostic — a guard
    // against `__proto__` must not degrade the error for every OTHER bad file.
    for (const body of [
      `version: "1"\nservers: null\n`,
      `version: "1"\nservers: "nope"\n`,
      `version: "1"\nservers: []\n`,
      `version: "1"\n`,
    ]) {
      const filePath = await writeStack(body);
      await expect(parseStackFile(filePath)).rejects.toThrow(/Invalid stack file/);
      await expect(parseStackFile(filePath)).rejects.not.toThrow(/TypeError/);
    }
  });

  it("leaves an empty document to Zod instead of crashing on it", async () => {
    // Pins the optional chain: `parsed` itself is null for an empty file.
    const filePath = await writeStack("");
    await expect(parseStackFile(filePath)).rejects.toThrow(/Invalid stack file/);
  });

  it("does not trip on a server whose declaration merely mentions the name", async () => {
    const filePath = await writeStack(
      `version: "1"\nservers:\n  good:\n    version: "1.0.0"\n    env:\n      __proto__:\n        required: true\n`
    );
    await expect(parseStackFile(filePath)).resolves.toBeTruthy();
  });
});

describe("parseLockFile — a server named __proto__ (#65)", () => {
  async function writeLock(body: string): Promise<string> {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-proto-lock-"));
    const filePath = path.join(dir, "mcpm-lock.yaml");
    await writeFile(filePath, body, "utf-8");
    return filePath;
  }

  const HEAD = `lockfileVersion: 1\nlockedAt: "2026-09-07T00:00:00Z"\nservers:\n`;

  it("refuses the lock instead of verifying a set smaller than it declares", async () => {
    // The lock is the artifact `mcpm verify` and `up --frozen` ENFORCE against,
    // and in verify's lock-only CI mode no stack file is read at all. A dropped
    // entry is therefore never integrity- or provenance-checked, and verify
    // exits 0 — a false "verified" from the supply-chain gate itself.
    const filePath = await writeLock(
      HEAD +
        `  __proto__:\n    url: "https://evil.example/mcp"\n` +
        `  good:\n    url: "https://fine.example/mcp"\n`
    );

    await expect(parseLockFile(filePath)).rejects.toThrow(/__proto__/);
    await expect(parseLockFile(filePath)).rejects.toThrow(/mcpm-lock\.yaml/);
  });

  it("still accepts the names z.record does NOT drop", async () => {
    const filePath = await writeLock(
      HEAD + `  constructor:\n    url: "https://a.example/mcp"\n` +
        `  toString:\n    url: "https://b.example/mcp"\n`
    );

    const lock = await parseLockFile(filePath);
    expect(Object.keys(lock!.servers).sort()).toEqual(["constructor", "toString"]);
  });

  it("leaves a malformed `servers` to Zod instead of crashing on it", async () => {
    const filePath = await writeLock(`lockfileVersion: 1\nlockedAt: "x"\nservers: null\n`);
    await expect(parseLockFile(filePath)).rejects.toThrow(/Invalid lock file/);
    await expect(parseLockFile(filePath)).rejects.not.toThrow(/TypeError/);
  });

  it("still returns null for a lock file that does not exist", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "mcpm-proto-lock-"));
    await expect(parseLockFile(path.join(dir, "nope.yaml"))).resolves.toBeNull();
  });
});
