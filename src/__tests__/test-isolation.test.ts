/**
 * Guards the suite's own isolation from the developer's real home directory.
 *
 * `vitest.setup.ts` disables the OS keychain, which pushes the secret store onto
 * its FILESYSTEM fallback under `~/.mcpm`. For a long time nothing redirected
 * HOME, so that fallback wrote to the developer's REAL home: test fixture secrets
 * landed in `~/.mcpm/secrets.enc.json` and test events accumulated in
 * `~/.mcpm/guard-events.jsonl` — polluting a security audit trail on every run.
 *
 * Nothing else in the suite fails if that redirect is removed (the tests still
 * pass — they just pass while writing to the wrong place), so this asserts it
 * directly.
 */

import { describe, it, expect } from "vitest";
import os from "node:os";
import path from "node:path";

describe("test isolation", () => {
  it("resolves HOME to a temp directory, never the developer's real home", () => {
    expect(process.env.HOME).toBeDefined();
    expect(path.basename(process.env.HOME!)).toMatch(/^mcpm-test-home-/);
    // os.homedir() is the route the store actually takes — assert the redirect
    // reaches it, not just the raw env var.
    expect(os.homedir()).toBe(process.env.HOME);
  });

  it("keeps the OS keychain disabled", () => {
    expect(process.env.MCPM_DISABLE_OS_KEYCHAIN).toBe("1");
  });
});
