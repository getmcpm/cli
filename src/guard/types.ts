/**
 * Shared types for the mcpm-guard runtime defense subsystem (v0.5.0).
 *
 * Severity, signature, and inspection-result types referenced across patterns,
 * relay, signatures, and demo modules. See the v0.5.0 design doc Section
 * "Signature format (YAML)" for the canonical shape.
 */

export type Severity = "critical" | "high" | "medium" | "low";

export type SignatureTarget =
  | "tool_response"
  | "tool_call_args"
  | "tool_description"
  | "tool_annotations"
  | "resource_content"
  | "prompt_content"
  | "initialize_instructions"
  // H7: a server-INITIATED sampling/elicitation prompt. Block-capable
  // pre-invocation context (NOT warn-only retrieved data) — kept OUT of
  // WARN_ONLY_TARGETS so a detected injection blocks (and is not re-clamped to
  // warn by applyPolicy). inspectServerInitiated re-tags its findings to this.
  | "sampling_prompt";

export interface Signature {
  readonly id: string;
  readonly category: string;
  readonly severity: Severity;
  readonly description: string;
  readonly target: SignatureTarget;
  readonly patterns: readonly RegExp[];
  readonly remediation: string;
}

export interface InspectFinding {
  readonly signature_id: string;
  readonly category: string;
  readonly severity: Severity;
  readonly target: SignatureTarget;
  readonly matched_text_excerpt: string;
  readonly remediation: string;
}

export type InspectAction = "pass" | "warn" | "block";

export interface InspectResult {
  readonly action: InspectAction;
  readonly findings: readonly InspectFinding[];
  /**
   * H7: when a server-INITIATED request (sampling/createMessage, elicitation/create)
   * is blocked, the synthetic JSON-RPC error must go back to the SERVER (the request's
   * origin / child), NOT to the client — the client never sent it. Undefined (default)
   * keeps existing behavior (error → client). Only meaningful when action === "block".
   */
  readonly replyToOrigin?: boolean;
}
