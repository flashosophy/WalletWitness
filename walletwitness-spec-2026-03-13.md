# WalletWitness Spec

Date: 2026-03-13
Status: Draft for implementation
Owner: Jun
Implementation: Codex

## 1. Trust Contract

### Product definition
WalletWitness provides cryptographic proof of who an AI system is talking to, binds that proof to a time-bounded trust session, and exposes a narrow policy surface for gating sensitive actions.

### Core problem
AI systems often know a user only through brittle app/session state:
- browser sessions can be stale or hijacked
- OAuth/session tokens prove account access, not present cryptographic control
- conversational continuity can create false confidence
- sensitive actions need stronger proof than ordinary chat

WalletWitness exists to answer:

> Who is this AI actually talking to, with cryptographic evidence, and what should that proof unlock?

### Core promises
1. **Proof** — verify wallet ownership cryptographically.
2. **Continuity** — preserve that proof as a time-bounded trust session.
3. **Control** — let the host app gate sensitive actions based on trust level and action scope.

### Non-goals
- Not a full auth replacement for every app.
- Not a complete permissions/roles platform.
- Not a wallet portfolio/dashboard product.
- Not an on-chain identity graph.
- Not a giant policy DSL.

### Trust states
- `anonymous`
- `authenticated_unverified`
- `verified_identity`
- `verified_action`

Each state must define:
- what evidence exists
- what it allows
- what it must not imply

Critical rule:

> Verified identity is not blanket permission.

### Contract boundary
WalletWitness owns:
- challenge issuance
- nonce / replay protection
- signature verification
- wallet + chain identity confirmation
- trust-session issuance and expiry
- verified-action grant issuance and expiry
- trust-state reporting helpers

Host apps own:
- business policy decisions
- action enforcement
- resource-specific authorization
- UI/product choices above the trust state

In short:

> WalletWitness proves and reports. The host app decides and enforces.

## 2. Threat Model

WalletWitness must explicitly defend against:
- replay attacks from reused signed challenges
- stale verification reuse after trust expiry
- session hijacking / stolen session tokens
- wrong-chain / wrong-wallet ambiguity
- UI claiming stronger trust than backend actually holds
- social engineering via conversational continuity or prior chat context
- permission inflation where `verified_identity` is treated as `verified_action`
- backend/frontend disagreement about current trust state

### Existing implementation rule
Where eva-core already has working, production-tested behavior, the spec should treat that implementation as ground truth to extract and generalize, not reinvent.

That includes in particular:
- challenge format
- nonce handling
- signature verification flow
- trust session generation
- expiry window behavior
- chain detection behavior

## 3. Behavior + Shape

This section deliberately combines user flows, API surfaces, and canonical objects so implementers do not need to cross-reference multiple sections to understand one concept.

### Canonical flows

#### Flow A — Verify identity
1. Client connects wallet.
2. Server issues challenge with nonce.
3. Client signs challenge.
4. Server verifies signature and wallet identity.
5. Server creates trust session.
6. Client/UI receives trust state `verified_identity`.

#### Flow B — Step up for sensitive action
1. User attempts protected action.
2. Host app asks policy with current trust state + requested action.
3. Policy denies ordinary identity if action requires step-up.
4. Client completes verified-action step.
5. Server issues bounded verified-action grant.
6. Action is allowed for that scope and time window only.

#### Flow C — Expiry / downgrade
1. Trust session or action grant expires.
2. Backend downgrades trust state.
3. Frontend reflects same downgraded state.
4. Sensitive actions re-require proof.

#### Flow D — Wrong chain / ambiguous chain
1. Wallet connects on wrong or ambiguous network.
2. Verification does not silently succeed.
3. UI shows clear mismatch state.
4. Trust state remains below verified identity until corrected.

### Canonical objects

#### `WalletIdentity`
```ts
interface WalletIdentity {
  address: string
  chainId: number
  walletType?: string
  label?: string
}
```

#### `VerificationRecord`
```ts
interface VerificationRecord {
  id: string
  wallet: WalletIdentity
  nonce: string
  issuedAt: string
  verifiedAt?: string
  expiresAt?: string
  signature?: string
  challengeText: string
  status: 'issued' | 'verified' | 'expired' | 'revoked'
}
```

#### `TrustSession`
```ts
interface TrustSession {
  sessionId: string
  principalId?: string
  identity: WalletIdentity
  trustLevel: 'anonymous' | 'authenticated_unverified' | 'verified_identity' | 'verified_action'
  verifiedAt?: string
  expiresAt?: string
  source: 'wallet_signature' | 'restored_session' | 'step_up'
}
```

#### `VerifiedActionGrant`
```ts
interface VerifiedActionGrant {
  id: string
  sessionId: string
  actionKey: string
  actionLabel?: string
  method?: string
  path?: string
  issuedAt: string
  expiresAt: string
}
```

#### `TrustPolicyDecision`
```ts
interface TrustPolicyDecision {
  allow: boolean
  reason?: string
  requiredTrust?: 'verified_identity' | 'verified_action'
}
```

### Minimal policy surface
MVP should expose one narrow callback:

```ts
type TrustPolicy = (input: {
  trust: TrustSession
  action?: {
    kind: string
    scope?: string
    method?: string
    path?: string
  }
}) => TrustPolicyDecision
```

This is intentionally small.
No policy DSL in MVP.

### UX rules
- UI must never imply stronger trust than backend actually holds.
- Trust state wording must be plain and exact.
- Expiry must be visible.
- Verified-action scope must be visible.
- Blocked actions must include a reason string.

### Deadbolt test
A normal developer should be able to:
- integrate basic identity verification in under 30 minutes
- protect one sensitive route/action without understanding all internals
- read trust state in plain language
- replace policy later without replacing the proof layer

If the package fails this test, the design is overbuilt.

## 4. Package Architecture

### `@walletwitness/core`
Owns:
- challenge issuance
- nonce / replay protection
- signature verification
- chain/account normalization
- trust session issuance
- verified action issuance
- trust-state evaluation helpers
- canonical types

No framework assumptions.

### `@walletwitness/server`
Owns:
- Express / Next / Hono middleware helpers
- challenge / verify route helpers
- cookie/header/session bridging
- protected-action middleware

### `@walletwitness/react` (or frontend package)
Owns:
- connect/sign helpers
- trust-state hooks
- trust badge / status components
- verified-action step-up prompts

### `walletwitness-demo`
Owns:
- reference app
- one minimal end-to-end integration example
- one protected action flow

## 5. MVP Scope

### Must-have in v1
- EVM wallet connect + sign challenge
- nonce + replay-safe verification
- trust session with expiry
- trust levels:
  - `anonymous`
  - `authenticated_unverified`
  - `verified_identity`
  - `verified_action`
- wrong-chain / chain-mismatch handling
- one narrow policy callback
- one backend integration example
- one frontend integration example
- one protected sensitive-action flow
- explicit downgrade/expiry behavior

### Not in MVP
- multi-wallet identity unions
- org/team trust graphs
- advanced policy composition
- giant role/permission matrix
- on-chain attestation storage
- analytics dashboards
- broad chain abstraction beyond the supported implementation target

## 6. Implementation Phases + Test Plan

### Phase 1 — Extraction from eva-core
- identify the production-tested challenge/verify/session code paths
- extract them into reusable core/server modules
- preserve known-good behavior before refactoring for elegance

### Phase 2 — Minimal package surface
- finalize canonical types
- finalize trust policy callback
- expose basic middleware/helpers
- wire one demo app

### Phase 3 — Protected action flow
- implement verified-action step-up
- bind grant to specific action scope + expiry
- add frontend/state visibility

### Phase 4 — Hardening + docs
- README with 30-second value prop
- one complete integration example
- explicit trust-state wording
- upgrade/downgrade semantics documented

### Test plan
Must verify:
- replay protection
- nonce invalidation
- signature verification correctness
- chain detection correctness
- wrong-chain rejection
- trust-session expiry + downgrade
- verified-action expiry + scope enforcement
- frontend/backend trust-state consistency
- policy callback behavior for allowed vs denied actions

### Acceptance criteria
WalletWitness is ready when:
- a developer can install, verify, and gate one action with minimal setup
- trust states are explicit and consistent across backend + UI
- wrong-chain and expired-session states degrade safely
- verified identity never silently acts as verified action
- extraction from eva-core preserves working production behavior

## Summary
WalletWitness should ship as a narrow, reusable trust layer for AI systems:
- cryptographic proof of present identity
- time-bounded trust session
- bounded step-up for sensitive actions
- small policy surface for host app control

The design target is not “auth platform.”
It is:

> a deadbolt for conversational trust.
