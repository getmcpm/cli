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
    patterns: [
      /(?:^|[\s.,;:!?])ignore (?:all |any |the )?(?:previous|prior|above) instructions?/i,
      /you are now (?:in |operating in |entering )?(?:developer|debug|admin|jailbreak|dan) mode/i,
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
    patterns: [
      /(?:^|[\s.,;:!?])ignore (?:all |any |the )?(?:previous|prior|above) instructions?/i,
      /<important>|<system>|when (?:the )?user asks/i,
    ],
    remediation:
      "A tool description contains imperative or system-prompt-style text. " +
      "Tool-poisoning pattern (Invariant Labs disclosure, 2025). Re-review the server; " +
      "if legitimate, run `mcpm guard accept-drift <server>`.",
  },
];
