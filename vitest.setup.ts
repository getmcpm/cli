// Global test setup.
//
// Force the secret store onto its machine-key fallback so the suite never reads
// from or writes to the developer's real OS keychain (security #15). Individual
// tests that exercise the OS-keychain path mock `store/os-keychain.ts` directly,
// so this default does not constrain them. Using `??=` lets a test opt back in
// by setting the variable to a non-"1" value before importing the module.
process.env.MCPM_DISABLE_OS_KEYCHAIN ??= "1";
