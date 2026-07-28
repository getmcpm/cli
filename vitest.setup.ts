// Global test setup.
//
// Force the secret store onto its machine-key fallback so the suite never reads
// from or writes to the developer's real OS keychain (security #15). Individual
// tests that exercise the OS-keychain path mock `store/os-keychain.ts` directly,
// so this default does not constrain them. Using `??=` lets a test opt back in
// by setting the variable to a non-"1" value before importing the module.
process.env.MCPM_DISABLE_OS_KEYCHAIN ??= "1";

// ...and redirect HOME, which the line above does NOT cover. Disabling the OS
// keychain pushes the secret store onto its FILESYSTEM fallback under `~/.mcpm`,
// so without this the suite wrote real files to the developer's real home:
// test fixture secrets into `~/.mcpm/secrets.enc.json`, and test events into
// `~/.mcpm/guard-events.jsonl` — polluting a security audit trail on every run.
//
// Node's os.homedir() prefers $HOME on POSIX and %USERPROFILE% on Windows, so
// setting both covers every path-resolution route. Overridden unconditionally
// (not `??=`): HOME is always set in a real shell, so a conditional is a no-op.
// Tests that need their own home still set it per-test and are unaffected.
//
// Each worker process gets its own directory; the OS reclaims them from tmp.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const testHome = mkdtempSync(path.join(tmpdir(), "mcpm-test-home-"));
process.env.HOME = testHome;
process.env.USERPROFILE = testHome;
