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
