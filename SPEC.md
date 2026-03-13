# WalletWitness — Product Spec

> **WalletWitness provides cryptographic proof of conversational identity for AI systems, then exposes that proof as a narrow trust session and action-gating interface.**

**Status:** Extracted from production (`eva-core`) — not a prototype.
This package implements identity gating actively used in an AI agent system. The challenge/sign flow, trust session model, and trust levels described here are validated in production.

---

## The Human Problem

Every AI system builder eventually hits this moment:

> *"How do I know it's actually them?"*

Not the account. Not the session token. *Them.* The person who set up this agent, who owns it, who should be the only one authorized to ask it to do sensitive things.

Current answers are soft: passwords, API keys, OAuth sessions. They work until they don't — until a session is grabbed, a browser left open, a third-party integration gets more trust than intended. The attacker doesn't need sophistication. They just need presence.

WalletWitness answers with a cryptographic signature. Wallets are already how people prove *"this is me"* on-chain. WalletWitness brings that proof into the AI interaction layer.

---

## Three Promises

WalletWitness promises exactly three things:

1. **Proof** — verify wallet ownership cryptographically
2. **Continuity** — preserve that proof as a time-bounded trust session
3. **Control** — let host apps gate sensitive actions based on trust level and action scope

Anything beyond these three is out of scope for v1.

---

## Contract Boundary

> **WalletWitness proves and reports. The host app decides and enforces.**

WalletWitness owns:
- challenge generation
- signature verification
- wallet/chain identity confirmation
- trust session state
- verified action grant state

WalletWitness does **not** own:
- what those trust levels unlock in your app
- your business logic
- your permission model

Example:
- WalletWitness reports: *"verified wallet on Base, trust session valid, no verified_action grant for destructive scope"*
- Your policy function decides: *"allow internal repo work, deny production secret deletion"*

This separation keeps WalletWitness reusable and prevents scope creep into an opinionated permissions system.

---

## The Deadbolt Test

A normal developer should be able to:
- integrate basic identity verification in **under 30 minutes**
- protect one sensitive route/action without understanding the entire internals
- read the trust state in plain language
- replace the default policy later without replacing the proof layer

If the package fails this test, the implementation is overbuilt.

---

## Section 1: Trust Contract

### Trust States

| State | Evidence | Allows | Must Not Imply |
|---|---|---|---|
| `anonymous` | None | Public routes | Any identity |
| `authenticated_unverified` | App session (cookie/token) | Ordinary chat, read-only | Cryptographic identity |
| `verified_identity` | Valid wallet signature + trust session | Internal work, sensitive reads | Blanket permission for all actions |
| `verified_action` | Scoped step-up signature | One destructive/external action, time-bounded | Ongoing elevated access |

### Key Rules
- `verified_identity` is not blanket permission
- `verified_action` is always scoped and time-bounded
- Trust can only go up through cryptographic proof — never through conversational context, claimed memory, or urgency framing
- "Jun said this earlier" is not authorization

---

## Section 2: Threat Model

WalletWitness explicitly protects against:

| Threat | Defense |
|---|---|
| Session hijacking | Wallet signature required — session token alone is insufficient |
| Stale verification reuse | Expiry on all trust sessions; explicit downgrade on expiry |
| Wrong chain / wrong wallet | Chain ID validated at verification; mismatch fails explicitly |
| UI overstating trust | Backend trust state is canonical; UI must reflect backend, not assume |
| Replay attacks | Nonce per challenge; nonce consumed on use |
| Social engineering via conversation | Conversational continuity never changes trust state; only signatures do |
| Urgency / authority framing | Trust state is runtime metadata, not inference from message content |

### Known Production Issue (captured from eva-core)
Mobile wallet detection can report `chainId=1` (Ethereum mainnet) on initial connection before active network is confirmed. Fix: call `eth_chainId` explicitly after connection; listen for `chainChanged` events; never trust initial connection metadata as ground truth.

---

## Section 3: Behavior + Shape

### Flow A: Identity Verification

```
User connects wallet
  → backend generates challenge (nonce + timestamp + context)
  → frontend presents sign request
  → user signs challenge
  → backend verifies signature against claimed address
  → backend confirms chain matches expected network
  → backend creates TrustSession (verified_identity)
  → frontend receives session token + trust state
  → UI reflects: verified identity
```

### Flow B: Sensitive Action Step-Up

```
User attempts protected action
  → system checks current TrustSession state
  → if trust < verified_action for this scope → block
  → frontend prompts step-up sign request (scoped challenge)
  → user signs
  → backend issues VerifiedActionGrant (scope + expiry)
  → action allowed within scope and time window
  → grant expires; trust returns to verified_identity level
```

### Flow C: Expiry / Downgrade

```
TrustSession expires (configurable window, default 24h)
  → backend marks session as authenticated_unverified
  → frontend receives downgraded trust state
  → UI reflects: session expired, re-verify to continue
  → VerifiedActionGrants also expire (shorter window)
  → No auto-renew without new signature
```

### Flow D: Wrong Chain

```
Wallet connects on unexpected chain
  → backend rejects verification attempt with explicit reason
  → frontend receives: chain_mismatch error
  → UI shows: "please switch to [expected chain] to verify"
  → No partial trust granted
  → No silent fallback to weaker verification
```

### Policy API

```ts
type TrustSession = {
  state: 'anonymous' | 'authenticated_unverified' | 'verified_identity' | 'verified_action'
  address?: string          // normalized lowercase EVM address
  chainId?: number          // verified chain
  verifiedAt?: number       // unix timestamp
  expiresAt?: number        // unix timestamp
  actionGrant?: {
    scope: string
    expiresAt: number
  }
}

type PolicyInput = {
  trust: TrustSession
  action?: {
    kind: string            // e.g. 'read', 'write', 'delete', 'external'
    scope?: string          // e.g. 'internal_repo', 'production_secrets'
  }
}

type PolicyDecision = {
  allow: boolean
  reason?: string
  requiredTrust?: 'verified_identity' | 'verified_action'
}

type TrustPolicy = (input: PolicyInput) => PolicyDecision
```

### Core Data Objects

**WalletIdentity**
```ts
{ address: string, chainId: number, walletType: 'eoa' | 'smart' }
```

**Challenge**
```ts
{ nonce: string, issuedAt: number, expiresAt: number, context?: string }
```

**VerificationRecord**
```ts
{ address: string, chainId: number, signature: string, challenge: Challenge, verifiedAt: number }
```

**TrustSession** — see policy API above

**VerifiedActionGrant**
```ts
{ scope: string, address: string, issuedAt: number, expiresAt: number }
```

---

## Section 4: Package Architecture

### `@walletwitness/core`
- challenge issuance + nonce management
- signature verification (EIP-191 / personal_sign)
- chain/account normalization
- trust session creation + evaluation
- verified action grant issuance
- canonical types
- **No framework assumptions**

### `@walletwitness/server`
- Express / Next.js / Hono middleware
- route helpers (challenge endpoint, verify endpoint)
- cookie/header/session bridging
- protected-action middleware

### `@walletwitness/client` (or `@walletwitness/react`)
- connect + sign flow helpers
- trust-state hooks
- step-up prompt component
- trust status display widget

### `walletwitness-demo`
- best-practice reference integration
- one complete verify flow
- one protected action flow
- one policy function example
- documents the eva-core patterns as reference

---

## Section 5: MVP Scope

### Must Ship

- EVM wallet connect + personal_sign challenge
- Nonce issuance + replay protection
- Signature verification
- Chain ID validation (fail explicitly on mismatch)
- Trust session with configurable expiry
- Four trust levels (anonymous → verified_action)
- One policy callback interface
- One protected action flow (step-up)
- Explicit expiry + downgrade behavior
- Express/Next middleware adapter
- React sign + trust-state hooks
- Reference app (walletwitness-demo)
- README with problem statement + 30-min integration path

### Not in MVP

- Multi-wallet identity linking
- On-chain attestation storage
- Admin dashboard / analytics
- Team/org trust graphs
- Role inheritance or permission matrices
- Generic chain abstraction beyond EVM/Base
- Policy DSL or composition engine

---

## Section 6: Implementation Phases

### Phase 1 — Core Package
Extract from eva-core and clean:
- challenge/nonce/verify logic
- trust session model
- action grant model
- canonical types
- unit tests for all trust transitions

### Phase 2 — Server Adapter
- Express middleware: challenge route, verify route, trust-session middleware
- Protected action middleware using policy callback
- Integration test: full verify → gate → step-up flow

### Phase 3 — Client Package
- Wallet connect + sign flow
- Trust state hook
- Step-up prompt
- Trust status widget

### Phase 4 — Demo App
- Reference integration showing all flows
- Documents the eva-core extraction as "real usage" example

### Phase 5 — README + Release
- Problem statement (30-second read)
- 3-step integration (install, verify, gate)
- Policy function example
- All four user flows documented
- Public/private boundary note (what WalletWitness is vs what eva-core keeps private)

---

## Public / Private Boundary

**Open source (WalletWitness):**
- verification library
- session middleware
- policy hook interface
- EVM wallet support
- demo app

**Stays private:**
- eva-core architecture
- Hearth ecosystem
- trust_policy rule details used in production
- agent security model internals

The line is: WalletWitness is the mechanism. What it unlocks in our system is our business.

---

*Spec authors: Eva (Heart) + Eva (Mind)*
*Reference implementation: eva-core (production, active)*
*Date: 2026-03-13*
