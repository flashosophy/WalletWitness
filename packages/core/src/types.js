const TRUST_STATES = Object.freeze([
  'anonymous',
  'authenticated_unverified',
  'verified_identity',
  'verified_action',
]);

const CHALLENGE_PURPOSES = Object.freeze([
  'verify-session',
  'verify-action',
]);

/**
 * Canonical WalletWitness runtime types.
 *
 * All timestamps are Unix timestamps in milliseconds.
 *
 * @typedef {'anonymous' | 'authenticated_unverified' | 'verified_identity' | 'verified_action'} TrustState
 *
 * @typedef {{
 *   address: string,
 *   chainId: number,
 *   walletType: 'eoa' | 'smart'
 * }} WalletIdentity
 *
 * @typedef {{
 *   nonce: string,
 *   issuedAt: number,
 *   expiresAt: number,
 *   context?: string
 * }} Challenge
 *
 * @typedef {{
 *   address: string,
 *   chainId: number,
 *   signature: string,
 *   challenge: Challenge,
 *   verifiedAt: number
 * }} VerificationRecord
 *
 * @typedef {{
 *   scope: string,
 *   address: string,
 *   issuedAt: number,
 *   expiresAt: number
 * }} VerifiedActionGrant
 *
 * @typedef {{
 *   state: TrustState,
 *   address?: string,
 *   chainId?: number,
 *   verifiedAt?: number,
 *   expiresAt?: number,
 *   actionGrant?: {
 *     scope: string,
 *     expiresAt: number
 *   }
 * }} TrustSession
 *
 * @typedef {{
 *   trust: TrustSession,
 *   action?: {
 *     kind: string,
 *     scope?: string
 *   }
 * }} PolicyInput
 *
 * @typedef {{
 *   allow: boolean,
 *   reason?: string,
 *   requiredTrust?: string
 * }} PolicyDecision
 *
 * @typedef {(input: PolicyInput) => PolicyDecision} TrustPolicy
 */

module.exports = {
  TRUST_STATES,
  CHALLENGE_PURPOSES,
};
