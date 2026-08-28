# mcpm ↔ OWASP MCP Top 10 mapping

This document maps mcpm's actual detection and enforcement mechanisms — guard
signatures, the tier-1 static scanner, and a handful of other subsystems — to
the OWASP MCP Top 10 (beta) categories, so a reader can tell exactly which
mcpm feature (if any) addresses a given category, and see the gaps stated
plainly rather than papered over.

**Pinned to commit
[`165fe0f78ef104459237b4a8e0f6e78db9b02391`](https://github.com/OWASP/www-project-mcp-top-10/tree/165fe0f78ef104459237b4a8e0f6e78db9b02391)
(`main`, 2026-07-29) of the
[OWASP MCP Top 10 project](https://github.com/OWASP/www-project-mcp-top-10),
`index.md`.** The list is explicitly a beta; OWASP may renumber or rename
categories in a future release, at which point this document needs to be
re-diffed against the new commit and re-pinned — treat every `MCP0x` label
below as tied to *this* commit, not to "OWASP MCP Top 10" as an evergreen
name. Category descriptions in this document are paraphrased in mcpm's own
words; see the source repo for the authoritative (CC BY-NC-SA 4.0) text.

**Disambiguation — do not confuse this with mcpm's internal catalog tags.**
`src/guard/signatures.ts` labels several entries `OWASP-MCP-1`,
`OWASP-MCP-2`, or `OWASP-MCP-7`. Those are leftover from the three
signatures mcpm vendored at launch (v0.5.0) from an *earlier* "OWASP MCP Top
10 v0.1" draft, where `mcp-1` meant tool-description injection, `mcp-2`
meant response injection, and `mcp-7` meant path exfiltration in arguments —
a different, since-renumbered scheme than the current beta list pinned
above (where, for example, `MCP01` means Token Mismanagement, not
description injection). This document's `MCP0x` numbers are derived fresh
from the mechanism against the *current* beta list; they should not be
read as consistent with those internal tag strings.

## Coverage map

| OWASP category | mcpm mechanism(s) | Honest justification |
|---|---|---|
| **MCP01 — Token Mismanagement & Secret Exposure** | Tier-1 hardcoded-secret scan (`detectSecrets`/`detectSecretLabels`, `src/scanner/patterns.ts`); installed-config plaintext-secret scan (`scanConfigSecrets`, `src/scanner/config-secrets.ts`); `credential-egress-in-response` + `generic-bearer-token-disclosure` guard signatures (`src/guard/signatures.ts`); an AES-GCM-encrypted secrets vault (`src/store/keychain.ts`) whose master key is held in the OS credential store (`src/store/os-keychain.ts`), not on disk | mcpm looks for credentials in three places a server can expose them — registry metadata, already-installed client configs, and live tool responses — and redacts what it catches before logging. Its own secrets vault also avoids at-rest exposure for values a user stores through mcpm (a copied `secrets.enc.json` cannot be decrypted off-machine). None of this tracks token *lifetime* (rotation, expiry); it's presence/leak detection, not lifecycle management. |
| **MCP02 — Privilege Escalation via Scope Creep** | Partial: `initialize`-handshake capability-drift detection (`classifyHandshakeDrift`/`buildHandshakeDriftFinding`, `src/guard/drift.ts`, H5) | mcpm TOFU-pins a server's declared capabilities at first observation and WARNs (never blocks) when they change on a later session; if the newly-added capabilities include `sampling` or `elicitation` — a channel the server can use to actively drive prompts to the model/user — the warning names it a "capability/grant escalation" in its own remediation text. This is genuinely scope-creep detection, but narrow: it only recognizes two specific capability keys as escalation-worthy, it fires only on a CHANGE from a TOFU baseline (a server that requests broad capabilities from its very first session is never flagged), and it has no concept of tool-level or argument-level scope at all. See the gap list for what remains uncovered. |
| **MCP03 — Tool Poisoning** | `owasp-mcp-1-tool-description-injection`, `owasp-mcp-2-instruction-injection-in-response`, `hidden-chars-in-metadata`, `unicode-tag-concealment` (all `src/guard/signatures.ts`); `exfil-param-in-schema` (`src/guard/exfil-params.ts` / `exfil-names.ts`); schema/description pin+drift detection (`src/guard/drift.ts`) | This is mcpm-guard's founding use case: it inspects tool descriptions, schemas, and a tool's own response content for injected or concealed manipulation, and separately re-verifies a previously-approved tool's description/schema/annotations on every `tools/list`, so poisoning introduced *after* approval (a rug-pull) is caught too. `instruction-injection-in-response` also has secondary relevance to MCP06 (same injected-phrase family, different carrier); `exfil-param-in-schema` also has secondary relevance to MCP10 (the schema field's purpose is inducing over-sharing of the model's own context). |
| **MCP04 — Software Supply Chain Attacks & Dependency Tampering** | npm Sigstore provenance identity + crypto verification (`fetchNpmProvenance`/`compareProvenance`, `src/registry/npm-provenance.ts`); verify-time provenance regression block (`classifyProvenance`, `src/stack/frozen-provenance.ts`); verify-time `dist.integrity` drift block (`classifyIntegrity`/`frozenVerdict`, `src/stack/frozen-verify.ts`); typosquatting detector (`detectTyposquatting`, `src/scanner/patterns.ts`); release-age cooldown (`assessReleaseAge`, `src/scanner/cooldown.ts`); registry lifecycle status check (`src/scanner/registry-status.ts`) | mcpm's second-deepest category: build-identity attestation, tarball-integrity re-verification, name-confusion detection, and a freshness/lifecycle check together target a tampered dependency or a poisoned republish from several independent angles — though only the npm registry type gets the cryptographic layer; pypi/oci packages are unverified. |
| **MCP05 — Command Injection & Execution** | `shell-metachar-in-identifier-arg` (`src/guard/shell-metachar-args.ts`); `query-control-syntax-in-identifier-arg` (`src/guard/query-control-args.ts`); `cli-flag-injection-in-identifier-arg` (`src/guard/cli-flag-injection-args.ts`); install-script / dangerous-launch-flag detector (`detectInstallScriptShape`, `src/scanner/patterns.ts`) | Three CVE-motivated structural detectors watch `tools/call` argument values for shell, query-language, or CLI-flag injection syntax — but, by design, only when the argument's own key looks like an identifier/path, to stay zero-FP on legitimate shell/query/exec-style tools. That is a deliberate, documented trade-off: some untyped or `name`-keyed injections pass through uncaught. |
| **MCP06 — Intent Flow Subversion** | `owasp-mcp-2-instruction-injection-in-resource`, `owasp-mcp-2-instruction-injection-in-prompt`, `owasp-mcp-1-initialize-instruction-injection`, `credential-phishing-wallet-solicitation`, `credential-phishing-financial-solicitation` (all `src/guard/signatures.ts`) | mcpm scans every context channel MCP exposes before or around a tool call — retrieved resources, prompt templates, and the `initialize` handshake — for the same imperative-injection phrase family, which is exactly the "context as a secondary instruction channel" shape this category describes. The credential-phishing pair is a specialized instance where the hijacked intent is soliciting the user's own secret (also relevant to MCP01). |
| **MCP07 — Insufficient Authentication & Authorization** | *No mechanism.* | Verified gap: mcpm has no caller-identity or access-control layer. Two adjacent-but-different things exist and must not be conflated with it — npm Sigstore provenance attests *who published* a package (a supply-chain claim, counted under MCP04), and the `initialize`-handshake drift check's IDENTITY dimension (`handshake-drift-identity`, `src/guard/drift.ts`) flags a server's self-reported name changing since first observed (anti-impersonation, not authorization or identity verification — mcpm never independently confirms the name was true in the first place). The same drift check's separate CAPABILITY dimension is a different signal, counted under MCP02 above, not here. |
| **MCP08 — Lack of Audit and Telemetry** | `guard-events.jsonl` append-only audit trail (`logEvent`, `src/guard/relay.ts`) | Real but partial coverage: a frame is appended only when the inspection produces at least one finding — a clean frame with zero findings is never logged (every catalog signature today resolves to at least `warn`, so in practice this means only `block`/`warn` verdicts are recorded, but the gate is "has findings," not "action ≠ pass") — so this is an audit trail of what the guard flagged, not the complete per-invocation record the category asks for. |
| **MCP09 — Shadow MCP Servers** | *No mechanism.* | Verified gap, and a deliberate non-mapping: mcpm's cross-server tool-shadowing check (`src/guard/shadow.ts`) is exact tool-*name* collision detection between two already-installed, already-guarded servers on one user's own machine. It has no concept of organizational approval and is blind to a server that was never guarded — a different problem from ungoverned server discovery/deployment across an org, despite the shared word "shadow." |
| **MCP10 — Context Injection & Over-Sharing** | *No dedicated mechanism* (see MCP03's `exfil-param-in-schema` for an adjacent, narrower case) | mcpm is architected as one relay wrapping one server for one session on one local machine — there is no shared or persistent multi-agent/multi-session context store for it to scope or isolate, which is the architecture this category assumes. `exfil-param-in-schema` blocks a narrower, different case (a poisoned tool schema tricking a single agent into leaking its own context outward) and is counted as tool poisoning under MCP03, not as coverage here. |

## Gap list

mcpm does not meaningfully address these categories (MCP02 has narrow partial
coverage noted in the table above; the rest have none):

- **MCP02 — Privilege Escalation via Scope Creep (partial only).** mcpm has
  no general model of an MCP server's granted permissions/scope — the
  handshake capability-drift check (see the table) recognizes exactly two
  capability keys (`sampling`, `elicitation`) as escalation-worthy, only
  detects a CHANGE from a TOFU baseline (not an overly-broad initial grant),
  and has no visibility into tool-level or argument-level scope at all.
  `guard --confine`'s OS-level sandbox (filesystem/network denylists on the
  spawned child process — the secret-directory read-denylist derivation is
  `src/guard/confine/derive.ts`, the network all-or-none policy is
  `src/guard/confine/profile.ts`) sits one layer below this — it bounds what
  any server can physically do regardless of the scope it claims, but it
  doesn't detect or govern scope *declarations*, so it isn't counted as
  coverage above.
- **MCP07 — Insufficient Authentication & Authorization.** mcpm is a local,
  single-user CLI and relay; nothing in the codebase authenticates a caller
  or enforces a permission boundary between agents, servers, or users.
- **MCP09 — Shadow MCP Servers.** mcpm has no organizational visibility
  into what servers exist or get deployed anywhere; its tool-shadowing
  check (see table) is a same-machine name-collision diagnostic, not
  ungoverned-deployment discovery.
- **MCP10 — Context Injection & Over-Sharing.** mcpm's guard operates
  per-session on one wrapped server; there is no shared or persistent
  context store across agents or users for it to scope or isolate, which
  is the scenario this category is primarily about.
