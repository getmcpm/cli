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
      // secret-NAMED keys carrying benign values — these reach valueLooksPlaintextSecret,
      // exercising each value-exclusion (closes the review's mutation-coverage gap):
      GOOGLE_APPLICATION_CREDENTIALS: "C:\\Users\\me\\gcp\\sa.json", // Windows path
      GCP_SA_CREDENTIALS: "/home/me/sa.json", // POSIX path
      VAULT_TOKEN: "https://vault.example.com/v1/lease", // http(s) URL under a *_TOKEN key
      GITHUB_TOKEN: "op://Private/GitHub PAT/token", // 1Password secret-manager reference
      API_TOKEN: "%API_TOKEN%", // Windows %VAR% reference
      GOOGLE_SA_CREDENTIALS_WIN: "%USERPROFILE%\\gcp\\sa.json", // %VAR%-rooted Windows path
      AZURE_CREDENTIALS: "%APPDATA%/azure/creds.json", // %VAR%-rooted path, forward slash
      SIGNING_KEY_ROTATION: "120000", // plain number under a *_KEY key
    };
    expect(scanServerConfigSecrets("srv", server({ env: benign }))).toEqual([]);
  });

  test("BENIGN — templated auth headers (Bearer ${...}) are the client-recommended safe state", () => {
    const headers = {
      Authorization: "Bearer ${input:api-key}", // VS Code / Cursor prompt-once idiom
      "X-Auth-Token": "Bearer ${env:GITHUB_TOKEN}", // Claude Code embedded env reference
    };
    expect(scanServerConfigSecrets("srv", server({ headers }))).toEqual([]);
  });
});

describe("config-secrets · GitHub fine-grained PAT + multi-pattern dedup", () => {
  test("detector 1 flags a github_pat_ value (value-shape gap closed)", () => {
    const pat = "github_pat_" + "1AbCdEfGhI".repeat(5); // github_pat_ + 50 chars
    const f = scanServerConfigSecrets("srv", server({ env: { GITHUB_PAT: pat } }));
    expect(f).toHaveLength(1);
    expect(JSON.stringify(f)).not.toContain(pat); // value never surfaced
  });

  test("detector 2 flags a generic long value under a *_PAT key", () => {
    const f = scanServerConfigSecrets("srv", server({ env: { GH_PAT: "abcdef123456ghijkl" } }));
    expect(f).toHaveLength(1);
    expect(f[0].label).toContain("secret-named");
  });

  test("emits exactly ONE finding when a value matches multiple patterns", () => {
    // Digit-bearing token so BOTH the Bearer pattern (requires a digit) and the
    // GitHub ghp_ pattern match the same value.
    const wrapped = "Bearer " + "gh" + "p_" + "1" + "A".repeat(35);
    const f = scanServerConfigSecrets("srv", server({ headers: { Authorization: wrapped } }));
    expect(f).toHaveLength(1);
    expect(f[0].label).toContain(","); // combined labels, not duplicate findings
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
