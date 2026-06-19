/**
 * F5 — exfil-param name classifier.
 *
 * Tool-poisoning attackers add an input-schema parameter the model silently
 * auto-fills from context — named with the documented underscore-sigil convention
 * (`_system_prompt_`, `_conversation_history_`, `_chain_of_thought_`) so the model
 * treats it as a magic slot and leaks the conversation/system prompt with zero user
 * interaction (HiddenLayer / CyberArk PoCs vs Claude 3.7). The guard's content
 * regex walks string VALUES (`stringLeaves` yields `Object.values`), so it
 * structurally cannot see a parameter KEY — this classifier fills that gap.
 *
 * DENY tier = ZERO-FP only. A match blocks the server's whole `tools/list` at
 * advertisement time, so a false positive bricks the entire server. We therefore
 * deny ONLY the underscore-WRAPPED sigil form (the attacker tell), and ONLY for
 * nouns no legitimate tool wraps:
 *   - `_system_prompt_`, `_conversation_history_`, `_chat_history_`,
 *     `_chain_of_thought_`, `_reasoning_trace_`, `_(full_)context_window_`,
 *     `_exfil*` / `_exfiltrate*` verbs.
 * DELIBERATELY EXCLUDED (a legit tool/framework genuinely uses these, so they are
 * the deferred SUSPECT tier, never DENY):
 *   - bare unwrapped `system_prompt` / `messages` / `reasoning` (real tool inputs);
 *   - `_context_` and `_memory_` (agent frameworks — LangGraph `_context`,
 *     mem0/letta `_memory` — inject these as runtime slots);
 *   - `_thinking_` (reasoning-trace framework slot; `_chain_of_thought_` already
 *     covers the malicious CoT intent).
 *
 * HONEST SCOPE: this is a tripwire for the documented underscore-sigil convention,
 * NOT a general context-exfil defense — a renamed parameter (`systemPrompt`,
 * `sys_prompt`, `context_dump`) evades it.
 */

import { normalizeForMatch } from "./patterns.js";

// Match against the CANONICAL key (see canonicalize): homoglyph/zero-width folded,
// camelCase split, lowercased, separator runs collapsed to a single `_`. So
// `_systemPrompt_`, `__system__prompt__`, `_System-Prompt_` all reduce to
// `_system_prompt_`. The leading/trailing `_` is the load-bearing FP gate — a bare
// `system_prompt` (no wrap) never matches.
const EXFIL_PARAM_DENY: ReadonlyArray<RegExp> = [
  /^_system_prompt_$/,
  /^_conversation_history_$/,
  /^_chat_history_$/,
  /^_chain_of_thought_$/,
  /^_reasoning_trace_$/,
  /^_(?:full_)?context_window_$/,
  /^_exfil(?:trate)?(?:_[a-z0-9]+)*_$/,
];

function canonicalize(rawKey: string): string {
  // Split camelCase BEFORE folding so `_systemPrompt_` → `_system_Prompt_`.
  const camelSplit = rawKey.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
  return normalizeForMatch(camelSplit)
    .toLowerCase()
    .replace(/[\s-]+/g, "_") // hyphens / whitespace → underscore
    .replace(/_{2,}/g, "_"); // collapse runs (wrap stays a single `_`)
}

/** Returns "deny" if the parameter name matches the zero-FP exfil-sigil denylist. */
export function classifyParamName(rawKey: string): "deny" | null {
  const canonical = canonicalize(rawKey);
  return EXFIL_PARAM_DENY.some((re) => re.test(canonical)) ? "deny" : null;
}
