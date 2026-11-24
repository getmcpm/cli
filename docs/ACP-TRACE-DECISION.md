# #159 ACP trace consumer decision — 2026-11-08

**Decision: defer the offline ACP spike; it remains unbuilt.** Evaluating mcpm's
actual development/release workflow found a real permission/cancellation review
consumer, whose available evidence is MCP and Claude native/SDK traffic. No
supplied ACP v1 trace or concrete ACP-specific review question beyond those logs
was identified in this scope. This applies the original backlog stop rule; it
does not require a production CLI, recurring use, blocked release or timing study.

## Pinned primary contract

This assessment pins the official
[ACP source](https://github.com/agentclientprotocol/agent-client-protocol/tree/7441d106a853682cce61d2dd7db54123e4b9a477)
at `7441d106a853682cce61d2dd7db54123e4b9a477`.
The [v1 schema](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/schema/v1/schema.json)
has 265,346 bytes, Git blob `b8e9574cda970ed288db60b56c528fc717b8b224`,
SHA-256 `e747a7bec3c02708b70885bf3cccac5c72fa421390dd7e85758fd61e33b1ae21`.
The five relevant v1 MDX pages, v1/v2 method metadata and navigation were checked
against their exact Git blob, size and SHA-256 bindings.

Pinned [navigation](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/docs.json)
labels v1 Latest and v2 Draft; its SHA-256 is
`75ed4aabfb2bf72249cdccf5b9a7b7fba64b3e8a25823cbe8915ff07c8b81d50`.
This stage observation is not inferred from the existence of v2 metadata.
ACP wire version is the negotiated integer `protocolVersion`; the schema's
artifact revision and a date-shaped MCP version are different identities.
Capabilities can evolve within v1, so a v1 label alone is not a complete profile.

## Actual consumer and evidence

The maintainer uses retained fixtures to accept/reject compatibility evidence
and inspect permission, cancellation and recovery. Those decisions already have
named assertions in `scripts/protocol-sandbox/run.mjs` and the native consent
helpers/self-checks. This is a consumer worth preserving, rather than evidence
that an ACP-specific adapter is currently needed.

| Inspected source or retained evidence | Observation and boundary |
| --- | --- |
| Runtime, scripts, dependencies/locks, workflows, contracts and maintainer references | No ACP transport, SDK dependency or trace-consumer path was found. ACP is a conditional research/backlog item. This was a scoped source inventory, not a search of private profiles or other projects. |
| Final #140 candidate and published protocol captures | Each report references 282 captures with 2,468 decoded wire messages. They contain MCP methods/date-version negotiation, including four `notifications/cancelled` messages. No decoded ACP session methods were observed. Two raw-large rows per artifact contain length/hash only; those bodies remain undecoded, not negative ACP proof. |
| MCP cancellation assertions | Slow calls bind `notifications/cancelled` to the actual MCP request ID. This is existing release-harness evidence, not ACP cancellation semantics. |
| Final #158 native receipt | Its 126 frames contain Claude SDK control, user/result, command-lifecycle and hook events, with zero JSON-RPC envelopes. A control subtype named `initialize` or a blocked prompt is not an ACP handshake or permission request. |
| Native permission/cancellation helpers | Existing checks cover dispatch before permission, deny/cancel and recovery in their named native fixtures. Source inspection here does not claim a fresh execution of the historical macOS consent suite. |
| CI/release retention | CI retains the synthetic MCP protocol artifact for 14 days; other workflows produce package/SARIF/SBOM/provenance evidence. None supplies the ACP input for this decision. MCP retention does not authorize retention of a future value-bearing ACP trace. |

The named retained files were read offline; no agent/client connection, native
validator, provider call, private configuration or credential-store read was
performed. This inventory cannot prove that ACP users or useful traces do not
exist elsewhere. The two hash-only rows and any uninspected material remain gaps.
No external ACP report was supplied, and converting these MCP/SDK frames into
ACP examples would manufacture the prerequisite rather than satisfy it.

## Original MVP and reopening conditions

Reopen for a named maintainer question, including a one-off review, supported by
one supplied, value-redacted **real ACP v1 trace** and a concrete usefulness case
beyond its existing logs. Qualitative ambiguity or review effort can justify the
bounded spike; a preimplementation timing benchmark is not required. Agree the
trace source/owner, byte binding, capture/redaction boundaries, size/record limits
and retention/deletion scope before using it. This decision authorizes no new
trace collection or outreach.

The full original offline fixture acceptance remains:

| Check | Required interpretation |
| --- | --- |
| Version and capture identity | Pin schema/capabilities and preserve connection direction, order, session and typed JSON-RPC IDs. Malformed/unknown revisions and unobserved capture boundaries remain incomplete. Agent/client names are self-reported, not security credentials. |
| Permission correlation | Bind the request, tool-call identity, offered options and selected `optionId`. Preserve reject-option meaning and cancelled outcomes distinctly. Missing permission traffic alone is not a violation: asking is optional. Labels and reported choices do not establish OS enforcement. |
| Prompt cancellation | For `session/cancel`, check pending permission replies and the original prompt's cancelled stop reason. Updates can legitimately arrive after the cancel notification and before the prompt reply. Missing replies or partial traces remain incomplete. |
| Generic cancellation | Treat `$/cancel_request` separately: support is optional, and propagation to nested work is not guaranteed. A request or reported cancelled outcome cannot prove that every child process stopped. |
| Negative fixtures and unknowns | Exercise missing/duplicate/mismatched replies, denied/cancelled distinctions, unknown profiles and partial/redacted observations. Lost evidence cannot inherit a clean aggregate. |
| Scope and privacy | Use only the supplied bounded trace/fixtures, retain redaction gaps and never fetch or execute trace-authored content. No v2 Draft implementation, live proxy, agent sandbox, A2A bridge or delegation platform. |

These distinctions follow the pinned
[initialization](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/protocol/v1/initialization.mdx),
[permission](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/protocol/v1/tool-calls.mdx),
[prompt-turn](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/protocol/v1/prompt-turn.mdx),
[cancellation](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/protocol/v1/cancellation.mdx)
and [security](https://github.com/agentclientprotocol/agent-client-protocol/blob/7441d106a853682cce61d2dd7db54123e4b9a477/docs/protocol/v1/security.mdx)
sources. ACP itself is not a process sandbox.

No ACP parser, runtime carrier or trace-validation result ships from this gate.
The documentation decision requires no npm release or companion repin.
