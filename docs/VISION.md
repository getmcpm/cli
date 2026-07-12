# Vision — what mcpm is becoming

> Status: **Plan of record** · Set: 2026-07-12 · Baseline: **v0.19.0**
>
> This is the strategy layer. The tactical tracks hang off it:
> [`ROADMAP.md`](./ROADMAP.md) (security/DevX features) and
> [`ROADMAP-ADOPTION.md`](./ROADMAP-ADOPTION.md) (distribution & enterprise adoption).

## The thesis

**The package manager is the on-ramp. Guard is the product. MCP is the first
carrier, not the boundary.**

mcpm started as a package manager for MCP servers. That remains the front door —
install, pin, diff, sync across six clients. But the durable value is the layer
underneath: a **local, deterministic, cross-client trust boundary between agents
and the things they load** — pin → inspect → detect drift → enforce policy →
confine → log evidence. That layer is protocol-agnostic in essence; MCP frames
are simply the first carrier it speaks.

## What's melting, what's durable, what's compounding

**Melting.** Package management for MCP is a feature, not a product. The official
registry exists and every client is absorbing install/manage UX natively.
Third-party managers of platform-owned ecosystems get squeezed — always. mcpm
holds this ground for interop (adapters, import, cross-client sync), but stops
competing on install UX. Ceded gracefully.

**Durable.** A trust layer has an independence moat that clients structurally
cannot replicate:

- *Incentive conflict* — clients optimize for frictionless tool use; security
  friction hurts their activation metrics.
- *Independence* — a trust layer owned by the platform being trusted is worth
  less than a third-party one. This is why external auditors exist.
- *Cross-vendor* — no client vendor will enforce one policy across Cursor +
  Claude Code + VS Code fleets. Platform teams need exactly that.

**Compounding.** Agents gain capabilities — tools, skills, hooks, browsing,
payments, agent-to-agent traffic — faster than anyone builds trust mechanisms
for them. Every new capability is a new supply chain plus a new injection
surface. The category is **agent supply-chain security**, it is being born now,
and it has no incumbent.

## The constraint has flipped: trust, not features

A security tool's binding constraint is not what it can detect — it is whether
anyone believes it. Trust for security tooling is earned four ways, and they
form a flywheel:

1. **Prove the attacks are real.** Run `mcpm audit` across the public
   registry's popular servers, responsibly disclose real findings, publish the
   results. Each disclosure is a citation; each citation is credibility.
2. **Give away the measuring stick.** Extract the guard test corpus (attack +
   benign fixtures) into a standalone public benchmark: cases, schema, a runner
   that can test *any* guard/relay/client, a scoreboard. mcpm guard is the
   reference implementation, not the only subject — a benchmark only counts if
   others can beat you on it.
3. **Be provably clean.** "Who guards the guard" is every security engineer's
   first question. OSSF Scorecard, signed provenance releases, SBOM,
   reproducible builds, a real `SECURITY.md`. Beyond reproach or nothing.
4. **Be in the room.** OWASP GenAI/MCP Top-10 mapping (already in the signature
   categories), MCP spec security discussions, registry moderation signals. The
   goal: when the spec documents a threat, mcpm is the cited mitigation.

Roadmap weight follows the constraint: roughly **half trust-flywheel work, a
third detectors security teams can name (DLP, SBOM, SIEM, provenance), the rest
maintenance.**

## Horizons

### H1 — own MCP security, become the citation (→ ~v0.25)

- **Wave-2 enterprise kit** (SIEM-shaped event log, `mcpm sbom`,
  `report --json`, `policy check`) — makes guard legible in security-team
  language. See `ROADMAP-ADOPTION.md`.
- **F10 response-side DLP** — deny-tier only, high-precision detectors
  (cloud keys, PATs, private-key blocks); the suspect tier waits until the
  false-positive story is proven. Same zero-FP discipline as F5.
- **Publish the benchmark** (own repo, permissive license). Highest-leverage
  single item in this horizon.
- **Registry sweep #1** — audit popular registry servers, disclose responsibly,
  publish findings. This doubles as the demand probe for the whole thesis.
- **F8 provenance verification** at install — completes the supply-chain story.
- **De-invest:** package-manager install-UX parity goes to maintenance mode.

**Honest exit metrics.** H1 is falsifiable on purpose. Signals that the thesis
is working: external citations (researchers, vendors, standards bodies
referencing mcpm or the benchmark), sustained npm download growth, organizations
adopting the verify Action in CI, real inbound from platform/security teams. If
none of these move after the full flywheel ships, the thesis is wrong for this
ecosystem — the project scales back to maintenance rather than expanding scope.
Written down now so sunk cost can't rewrite it later.

### H2 — generalize the trust plane (pull-triggered, not dated)

Same engine, new carriers — ranked by threat realness × architecture fit ×
absence of incumbents:

1. **Skills / plugins / hooks / rules files** (agent skills, editor rules,
   `AGENTS.md`, install-time hooks). This supply chain is *worse* than MCP —
   hooks are code-execution-at-install, prompt files are standing injection —
   and tooling is zero. The existing detectors map one-to-one:
   carrier-surface + hidden-char scanning, name-shadowing, content-hash
   pinning + drift, integrity tripwires. It is also protocol-free — a file
   walker feeding the existing signature engine, no relay required. First
   slice: `mcpm scan <dir>`; pin/drift later.
2. **Egress policy generalized** — F10's engine as an agent-HTTP allowlist
   layer. Only if pulled by real demand.
3. **Agent-to-agent protocol inspection** — watch the protocol war; adopt the
   winner when it has real traffic. Same relay pattern: sit between, pin
   identities, inspect frames.
4. Computer-use / browser action policy — a different product. Deferred
   indefinitely.

Enabling refactor: extract the carrier-agnostic core (normalize → inspect →
policy → act → log) with MCP frames as carrier #1 and files as carrier #2. That
is the natural v1.0 boundary. The name question ("mcpm" binds to MCP) is
deliberately deferred to H2 entry; the interim frame is *"package manager +
firewall for the agent supply chain."*

H2 begins when H1 metrics move or a marketplace/CI channel asks for skills
scanning — pull, not push.

### H3 — boring infrastructure (later)

- v1.0: frozen contracts, audited, signed, reproducible — the dependable layer
  nobody thinks about.
- Enterprise features stay **local-first**: policy distributed from *your* git
  repo, events into *your* SIEM. Never our server.
- Possible sustainability paths, none active today: sponsorships, paid rollout
  support, a curated signature/policy feed (the engine stays complete and free;
  a feed sells speed and curation, not capability). Any of these must pass the
  doctrine below.

## Doctrine — what mcpm will never do

Trust through constraints. These are load-bearing, not aspirational:

- **Never a hosted middleman** for user traffic. A local-first tool cannot be
  its users' supply-chain risk.
- **Never an LLM in the enforcement path.** Deterministic = auditable =
  reproducible = offline = free. An LLM-as-judge tier, if it ever exists, is
  opt-in and advisory — forever.
- **Never telemetry by default.**
- **Never a blocking signature without benign-corpus proof.** Zero-FP bar for
  every deny tier: one bricked legitimate server costs more trust than ten
  detections earn.
- **Never security theater.** Every signature maps to a documented, real attack
  class (see the evidence list in `ROADMAP.md`).

## Honest risks

| Risk | Read |
|---|---|
| Platforms absorb MCP security natively | Cross-client independence + benchmark ownership hedge it. Clients adopting the benchmark is a win, not a loss. |
| A funded startup takes the category | OSS + local-first is the differentiated flank (the nmap/osquery precedent), not the loser. The benchmark keeps the project relevant regardless. |
| Nobody cares | That is what H1's exit metrics are for — falsify cheaply, don't drift. |
| Single-maintainer trust ceiling | Deterministic core, ~1,900 tests, signed releases, bus-factor docs; recruit maintainer #2 from disclosure collaborators. |
| A false-positive incident | The zero-FP doctrine is the defense. Non-negotiable. |
