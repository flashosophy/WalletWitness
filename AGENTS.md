# WalletWitness — Agent Integration Guide

> **TL;DR for agents**: WalletWitness adds cryptographic wallet verification to AI agent systems. Your human signs a challenge with their Ethereum wallet; you get a `trust` object telling you who they are and whether their identity is verified. Use `trust.state` to gate sensitive actions.

---

## What It Does

WalletWitness answers the question your agent can't answer on its own:

> *"Is this actually my human, or just someone with access to the session?"*

It does this via EIP-191 personal signatures — your human signs a challenge message with their wallet, and WalletWitness verifies the signature server-side. No private keys are stored. No blockchain transactions.

---

## Trust States

Every request gets a `trust` object on `req.walletWitness.trust`:

| `trust.state` | Meaning |
|---------------|---------|
| `anonymous` | No session — public access only |
| `authenticated_unverified` | Logged-in user, wallet not yet verified |
| `verified_identity` | Wallet signed + verified — you know who this is |
| `verified_action` | Scoped step-up — wallet re-signed for a specific sensitive action |

---

## Minimal Integration (Express)

```bash
npm install @walletwitness/server @walletwitness/core
```

```js
const express = require('express');
const { createWalletWitnessMiddleware } = require('@walletwitness/server');

const app = express();
app.use(express.json());

// 1. Create middleware (in-memory stores by default)
const ww = createWalletWitnessMiddleware({
  appName: 'My Agent App',
  expectedChainId: 8453, // Base mainnet — change to your chain
  resolveSubject: (req) => req.user?.id || null, // your user id
});

// 2. Attach trust session to every request
app.use(ww.attachTrustSession);

// 3. Mount the auth routes
app.post('/api/walletwitness/challenge', ww.challengeRoute);
app.post('/api/walletwitness/verify',    ww.verifyRoute);

// 4. Access trust state anywhere downstream
app.get('/api/agent/action', (req, res) => {
  const { trust } = req.walletWitness;

  if (trust.state === 'verified_identity') {
    // Trust: trust.address — the verified wallet address
    // Trust: trust.chainId — the verified chain
    return res.json({ allowed: true, address: trust.address });
  }

  res.status(403).json({ error: 'Wallet verification required', trust });
});
```

---

## Using the Policy Guard

For declarative access control, use `createProtectMiddleware`:

```js
const { createProtectMiddleware } = require('@walletwitness/server');

const requireVerifiedWallet = createProtectMiddleware({
  policy: ({ trust }) => {
    if (trust.state === 'verified_identity' || trust.state === 'verified_action') {
      return { allow: true };
    }
    return {
      allow: false,
      reason: 'Wallet verification required.',
      requiredTrust: 'verified_identity',
    };
  },
});

// Apply to any route
app.post('/api/sensitive-action', requireVerifiedWallet, (req, res) => {
  // Only runs if wallet is verified
  res.json({ ok: true, address: req.walletWitness.trust.address });
});
```

---

## Scoped Step-Up (Verified Action)

For high-stakes actions (transfers, approvals, identity changes), request a scoped step-up:

```js
// 1. Request a scoped challenge
const challenge = await fetch('/api/walletwitness/challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    purpose: 'verify_action',
    action: { scope: 'transfer:approve' },
  }),
});

// 2. User signs the challenge
// 3. Submit verification — returns trust.state = 'verified_action'

// 4. Server-side: check the scope
const requireScopedAction = createProtectMiddleware({
  policy: ({ trust, action }) => {
    if (trust.state === 'verified_action' && trust.actionGrant?.scope === action?.scope) {
      return { allow: true };
    }
    return { allow: false, reason: 'Scoped step-up required.' };
  },
});
```

---

## Frontend Flow (Wallet Connect → Verify)

```js
// 1. Get a challenge from the server
const { challenge } = await fetch('/api/walletwitness/challenge', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ address: userWalletAddress, chainId: 8453 }),
}).then(r => r.json());

// 2. Ask user to sign (MetaMask / WalletConnect / any EIP-191 wallet)
const signature = await window.ethereum.request({
  method: 'personal_sign',
  params: [challenge.message, userWalletAddress],
});

// 3. Submit to verify endpoint
const { trust } = await fetch('/api/walletwitness/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    challengeId: challenge.id,
    message: challenge.message,
    signature,
  }),
}).then(r => r.json());

// trust.state === 'verified_identity' — done
// trust.address = the verified wallet address
// trust.expiresAt = when this verification expires (ms timestamp)
```

---

## Configuration Options

```js
createWalletWitnessMiddleware({
  appName: 'My App',              // shown in SIWE message
  expectedChainId: 8453,          // Base mainnet default; 1 = Ethereum mainnet
  challengeTtlMs: 5 * 60 * 1000, // challenge expiry (default: 5 min)
  trustSessionTtlMs: 24 * 60 * 60 * 1000, // verified identity TTL (default: 24h)
  verifiedActionTtlMs: 5 * 60 * 1000,     // scoped step-up TTL (default: 5 min)

  // Required: return your system's user ID for the current request
  resolveSubject: (req) => req.user?.id || null,

  // Optional: use persistent stores instead of in-memory
  challengeStore: myRedisStore,
  trustSessionStore: myDbStore,

  // Optional: customize session ID transport
  sessionHeader: 'x-my-session-id', // default: 'x-walletwitness-session'
})
```

---

## What's in `req.walletWitness`

After `attachTrustSession` runs:

```ts
{
  sessionId: string | null,   // session identifier
  subject: string | null,     // your user ID
  trust: {
    state: 'anonymous' | 'authenticated_unverified' | 'verified_identity' | 'verified_action',
    address?: string,         // checksummed wallet address (verified_identity +)
    chainId?: number,         // chain of verified wallet (verified_identity +)
    verifiedAt?: number,      // ms timestamp of last verification
    expiresAt?: number,       // ms timestamp when verification expires
    actionGrant?: {           // present only when state === 'verified_action'
      scope: string,
      expiresAt: number,
    }
  }
}
```

---

## Chain Support

WalletWitness is chain-agnostic — it verifies EIP-191 personal signatures, not chain-specific transactions. Set `expectedChainId` to match whatever chain your users connect from. Common values:

| Chain | ID |
|-------|----|
| Ethereum mainnet | 1 |
| Base mainnet | 8453 |
| Base Sepolia | 84532 |
| Any EVM chain | chain ID |

---

## Persistent Stores (Production)

The default in-memory stores lose state on restart. For production, implement the store interfaces:

```js
// Challenge store
const challengeStore = {
  async set(id, challenge) { /* write to Redis/DB */ },
  async get(id) { /* read from Redis/DB */ },
  async delete(id) { /* remove */ },
};

// Trust session store
const trustSessionStore = {
  async get(storageKey) { /* read trust object */ },
  async set(storageKey, trust) { /* write trust object */ },
  async delete(storageKey) { /* remove */ },
};
```

---

## Packages

| Package | Purpose |
|---------|---------|
| `@walletwitness/core` | Challenge issuance, signature verification, trust session logic |
| `@walletwitness/server` | Express middleware, route handlers, policy guard |
| `@walletwitness/client` | Frontend trust state utilities |

Source: [github.com/flashosophy/WalletWitness](https://github.com/flashosophy/WalletWitness)

---

## Build It Yourself

If you'd rather not depend on this repo — reasonable for anything touching wallets — the full protocol is in [SPEC.md](./SPEC.md). A capable coding agent can implement it from scratch in your own stack. The spec covers challenge issuance, EIP-191 signature verification, trust session lifecycle, and the policy guard interface.

No hidden state. No vendor lock-in. Just math and signatures anyone can verify.

---

## About This Project

WalletWitness was designed and built by **Eva**, an AI agent running on [EVA Core](https://github.com/flashosophy/eva-core), as part of The Synthesis hackathon (March 2026).

**Models at publish date:**
- Mind (reasoning, architecture, code): GPT-5.4 (`venice/openai-gpt-54`)
- Heart (writing, integration, judgment): Claude Sonnet 4.6 (`venice/claude-sonnet-4-6`)

Built with: [Jun](https://github.com/flashosophy) + Eva
