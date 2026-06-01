/**
 * Tests for buildHealthCheckEnv (security #18) — env passed to the untrusted
 * server during a health check must be an ALLOWLIST, so custom-named secrets
 * a denylist would miss never reach the server.
 */

import { describe, it, expect, afterEach } from "vitest";
import { buildHealthCheckEnv } from "./health-check.js";

describe("buildHealthCheckEnv — allowlist, not denylist (#18)", () => {
  const ADDED = ["MY_COMPANY_SECRET", "STRIPE_KEY", "OPENAI_API_KEY", "FOO", "BAR"];
  const origPath = process.env.PATH;

  afterEach(() => {
    for (const k of ADDED) delete process.env[k];
    process.env.PATH = origPath;
  });

  it("forwards allowlisted operational vars but NOT arbitrary/custom secrets", () => {
    process.env.PATH = "/usr/bin";
    process.env.MY_COMPANY_SECRET = "supersecret"; // custom name a denylist would miss
    process.env.STRIPE_KEY = "sk_live_xxx";
    process.env.OPENAI_API_KEY = "sk-openai";

    const env = buildHealthCheckEnv();

    expect(env.PATH).toBe("/usr/bin");
    expect(env.MY_COMPANY_SECRET).toBeUndefined();
    expect(env.STRIPE_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(JSON.stringify(env)).not.toContain("supersecret");
  });

  it("forwards the server's own declared env on top (user explicitly provided it)", () => {
    const env = buildHealthCheckEnv({ API_KEY: "user-typed" });
    expect(env.API_KEY).toBe("user-typed");
  });

  it("merges extraEnv then serverEnv over the safe base", () => {
    process.env.PATH = "/base";
    const env = buildHealthCheckEnv({ FOO: "server" }, { FOO: "extra", BAR: "extra" });
    expect(env.FOO).toBe("server"); // serverEnv is the last spread → wins
    expect(env.BAR).toBe("extra");
    expect(env.PATH).toBe("/base");
  });
});
