/**
 * Scanner module barrel export.
 *
 * Re-exports the public API for the trust assessment scanner:
 * - patterns:    detectSecrets, detectPromptInjection, detectTyposquatting, detectExfilArgs
 * - tier1:       scanTier1, Finding type
 * - tier2:       checkScannerAvailable, scanTier2
 * - trust-score: computeTrustScore, TrustScore, TrustScoreInput
 */

export type { Finding } from "./tier1.js";
export { scanTier1 } from "./tier1.js";

export {
  detectSecrets,
  detectPromptInjection,
  detectTyposquatting,
  detectExfilArgs,
  type ArgSchema,
} from "./patterns.js";

export { checkScannerAvailable, scanTier2 } from "./tier2.js";
export type { Tier2Options, ExecResult, ExecImpl } from "./tier2.js";

export { computeTrustScore } from "./trust-score.js";
export type { TrustScore, TrustScoreInput, TrustScoreBreakdown } from "./trust-score.js";
