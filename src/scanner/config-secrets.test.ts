import { describe, expect, test } from "vitest";
import { scanConfigSecrets, scanServerConfigSecrets } from "./config-secrets.js";
import { toPlaceholder } from "../store/keychain.js";
import type { McpServerEntry } from "../config/adapters/index.js";

// Credential-shaped strings are assembled at runtime so no real-looking literal
// ever lands in source (GitHub push-protection / secret scanners; repo constraint).
const ghToken = "gh" + "p_" + "A".repeat(36);
const awsKey = "AKIA" + "ABCDEFGHIJ123456"; // AKIA + 16 upper/digit
const bearer = "Bearer " + "a".repeat(30) + "1"; // ≥20 token chars incl. a digit

const server = (over: Partial<McpServerEntry> = {}): McpServerEntry => ({
  command: "node",
  args: ["s.js"],
  ...over,
});

describe("config-secrets · detector 1 (value-shape)", () => {
  test("flags a known-format secret in an env value, regardless of key name", () => {
    const f = scanServerConfigSecrets("srv", server({ env: { HARMLESS_NAME: awsKey } }));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ server: "srv", field: "env", key: "HARMLESS_NAME" });
    expect(f[0].label).toMatch(/AWS/i);
  });

  test("flags a GitHub token and a Bearer token in headers", () => {
    const f = scanServerConfigSecrets(
      "srv",
      server({ env: { GITHUB_TOKEN: ghToken }, headers: { Authorization: bearer } })
    );
    expect(f.map((x) => x.field).sort()).toEqual(["env", "header"]);
    expect(f.find((x) => x.field === "header")?.label).toMatch(/bearer/i);
  });
});

describe("config-secrets · detector 2 (secret-named key heuristic)", () => {
  test("flags a plaintext value in a secret-named env key no pattern matches", () => {
    const f = scanServerConfigSecrets("srv", server({ env: { DB_PASSWORD: "hunter2xyz" } }));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ key: "DB_PASSWORD", label: expect.stringContaining("secret-named") });
  });

  test("normalizes hyphenated header keys (X-API-Key → API_KEY)", () => {
    const f = scanServerConfigSecrets("srv", server({ headers: { "X-API-Key": "abcdef123456" } }));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ field: "header", key: "X-API-Key" });
  });
});

describe("config-secrets · exclusions", () => {
  test("skips values already stored as mcpm:keychain: placeholders", () => {
    const ph = toPlaceholder("srv-hash", "GITHUB_TOKEN");
    expect(scanServerConfigSecrets("srv", server({ env: { GITHUB_TOKEN: ph } }))).toEqual([]);
  });

  test("BENIGN CORPUS — realistic non-secret config produces ZERO findings (zero-FP gate)", () => {
    const benign: Record<string, string> = {
      API_URL: "https://api.example.com",
      TOKEN_URL: "https://auth.example.com/oauth/token", // TOKEN + URL qualifier
      AUTH_TOKEN: "${AUTH_TOKEN}", // env reference, not a literal
      SECRET_NAME: "vault/prod/db", // descriptor, not the secret
      AWS_ACCESS_KEY_ID: "someaccountid", // _ID qualifier + non-secret-shaped value
      PUBLIC_KEY: "ssh-ed25519 AAAAsomekeymaterialthatislong", // not a *_KEY compound
      SESSION_TIMEOUT: "60000",
      DATABASE_PATH: "/var/lib/db.sqlite",
      LOG_LEVEL: "debug",
      PORT: "3000",
      ENABLED: "true",
      REGION: "us-east-1",
      PASSWORD: "", // empty
      SECRET_KEY: toPlaceholder("srv-hash", "SECRET_KEY"), // already stored
      TOKEN: "${MY_TOKEN}", // reference
      APIKEY_FORMAT: "hex", // FORMAT qualifier
      CONTENT_TYPE: "application/json",
    };
    expect(scanServerConfigSecrets("srv", server({ env: benign }))).toEqual([]);
  });
});

describe("config-secrets · redaction contract + aggregation", () => {
  test("a finding NEVER contains the matched value", () => {
    const f = scanServerConfigSecrets("srv", server({ env: { GITHUB_TOKEN: ghToken } }));
    expect(JSON.stringify(f)).not.toContain(ghToken);
    expect(f[0].key).toBe("GITHUB_TOKEN");
  });

  test("scanConfigSecrets aggregates across every server in a client", () => {
    const f = scanConfigSecrets({
      a: server({ env: { API_KEY: "plaintextvalue1" } }),
      b: server({ env: { X: "ok" }, headers: { Authorization: bearer } }),
      c: server({ env: { GITHUB_TOKEN: toPlaceholder("c-hash", "GITHUB_TOKEN") } }), // safe
    });
    expect(f.map((x) => x.server).sort()).toEqual(["a", "b"]);
  });
});
