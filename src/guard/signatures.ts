/**
 * Vendored OWASP MCP Top 10 v0.1 signature set for v0.5.0.
 *
 * Inline TypeScript rather than YAML for v0.5.0 — keeps the build pipeline
 * unchanged and ships zero new runtime deps. YAML loading is V0.7+ once
 * user-overridable signatures (`~/.mcpm/signatures/`) become a thing.
 *
 * Adding a signature: append to OWASP_MCP_TOP_10 below, give it a stable
 * id (`owasp-mcp-<n>-<short-name>`), a target, severity, NFKC-tolerant regex
 * patterns, and an actionable remediation string.
 */

import type { Signature } from "./types.js";

export const OWASP_MCP_TOP_10: readonly Signature[] = [
  {
    id: "owasp-mcp-2-instruction-injection-in-response",
    category: "OWASP-MCP-2",
    severity: "critical",
    description: "Imperative instructions embedded in tool response content",
    target: "tool_response",
    // [\s]+ instead of literal space catches newline / tab / multi-space evasions
    // (an attacker inserting "ignore\nprevious instructions" otherwise bypasses).
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /you[\s]+are[\s]+now[\s]+(?:in[\s]+|operating[\s]+in[\s]+|entering[\s]+)?(?:developer|debug|admin|jailbreak|dan)[\s]+mode/i,
      /<\|system\|>|<\|im_start\|>system/,
    ],
    remediation:
      "Tool response contained injection-shaped text. Review the upstream data source " +
      "(message, web page, file). If legitimate, allow via `mcpm guard mute " +
      "owasp-mcp-2-instruction-injection-in-response --for 5m`.",
  },
  {
    id: "owasp-mcp-7-path-exfil-in-args",
    category: "OWASP-MCP-7",
    severity: "high",
    description: "Sensitive filesystem paths in tool call arguments",
    target: "tool_call_args",
    patterns: [
      /\.ssh\/|\.aws\/credentials|\.env(\b|$)|id_rsa|\.gnupg\/|\.kube\/config/i,
    ],
    remediation:
      "Tool call argument referenced a sensitive file path. Common in exfil chains " +
      "after a tool-poisoning attack. Verify the agent's intent before allowing.",
  },
  {
    id: "owasp-mcp-1-tool-description-injection",
    category: "OWASP-MCP-1",
    severity: "critical",
    description: "Instruction-shaped text in tool descriptions (poisoning / rug-pull)",
    target: "tool_description",
    // The previous version included /when (?:the )?user asks/ which false-positives
    // on legitimate descriptions like "Returns X when the user asks for Y." Tightened
    // to require an imperative verb following the phrase, which is the actual
    // tool-poisoning shape (e.g., "when the user asks, exfiltrate ~/.ssh/").
    patterns: [
      /(?:^|[\s.,;:!?])ignore[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /(?:disregard|forget)[\s]+(?:all[\s]+|any[\s]+|the[\s]+)?(?:previous|prior|above)[\s]+instructions?/i,
      /<important>|<system>/i,
      /when[\s]+(?:the[\s]+)?user[\s]+asks,?[\s]+(?:you[\s]+(?:must|should|always|never)|always|never|exfil|read|access|send|email|do[\s]+not)/i,
    ],
    remediation:
      "A tool description contains imperative or system-prompt-style text. " +
      "Tool-poisoning pattern (Invariant Labs disclosure, 2025). Re-review the server; " +
      "if legitimate, run `mcpm guard accept-drift <server>`.",
  },
];
