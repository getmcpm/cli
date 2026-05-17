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
  | "tool_annotations";

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
}
