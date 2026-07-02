# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities through
[GitHub's private vulnerability reporting](https://github.com/getmcpm/cli/security/advisories/new)
rather than opening a public issue. We aim to acknowledge a report within **48 hours**
and will coordinate a fix and disclosure timeline with you.

For trust-assessment issues that are not themselves vulnerabilities — a false
positive or false negative in the scanner or guard signatures — a regular
[GitHub issue](https://github.com/getmcpm/cli/issues) is the right channel.

## Scope

**In scope:** the mcpm CLI itself — the installer/adapter layer that writes MCP
client configs, the trust scanner, the `guard` stdio relay and its signatures, the
lockfile/integrity machinery, and the `--confine` OS sandbox.

**Out of scope:** the behaviour of third-party MCP servers you install. mcpm's job is
to *assess and contain* them; a malicious or vulnerable upstream server is the threat
mcpm defends against, not a vulnerability in mcpm. Report those to the server's own
maintainers. (If mcpm *fails to detect or contain* something it claims to, that is in
scope.)

## Supported versions

mcpm is pre-1.0 (`0.x`). Only the **latest published minor** on npm
(`@getmcpm/cli`) receives security fixes; there is no long-term-support branch yet.
Upgrade to the latest release before reporting, in case the issue is already fixed.

| Version | Supported |
|---------|-----------|
| latest `0.x` minor | ✅ |
| older | ❌ (upgrade) |

## Supply chain (of mcpm itself)

mcpm is a security tool, so we hold our own release pipeline to the controls we ask
you to expect from upstreams:

- **Signed provenance.** Every release is published with
  `pnpm publish --provenance`, producing an npm/Sigstore build attestation that ties
  the published tarball to this repository and the GitHub Actions workflow that built
  it. Verify it yourself:

  ```
  npm audit signatures            # after installing @getmcpm/cli
  npm view @getmcpm/cli dist.attestations
  ```

- **Machine-readable SBOM.** A CycloneDX SBOM (`mcpm.cdx.json`) is generated from the
  committed `pnpm-lock.yaml` and attached to each [GitHub release](https://github.com/getmcpm/cli/releases).
- **Pinned, reviewed CI.** All GitHub Actions are pinned to full commit SHAs;
  `.github/workflows/` changes require review via `CODEOWNERS`. Dependencies are
  installed from a frozen lockfile and tracked by Dependabot.
- **No telemetry.** mcpm sends no usage data, install pings, or crash reports. It only
  contacts the MCP registry and package registries to resolve the servers you ask it
  to, and never phones home about mcpm itself.
- **Continuous scoring.** Project health is published via
  [OpenSSF Scorecard](https://github.com/getmcpm/cli/actions/workflows/scorecard.yml).
