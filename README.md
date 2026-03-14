# WalletWitness

> *Cryptographic proof of who your AI is talking to — not just a session token.*

Every AI system builder eventually hits this moment:

**"How do I know it's actually them?"**

Not the account. Not the browser session. *Them.* The person who built this agent, who owns it, who should be the only one authorized to ask it to do sensitive things.

Passwords and session tokens work until they don't — until a tab is left open, a token gets leaked, or a third-party integration inherits more trust than you intended. The attacker doesn't need sophistication. They just need presence.

WalletWitness answers with a cryptographic signature. Wallets are already how people prove *"this is me"* on-chain. WalletWitness brings that proof into the AI interaction layer.

---

## Three Promises

WalletWitness does exactly three things and nothing else:

1. **Proof** — verify wallet ownership via a challenge/sign/verify flow (EIP-191)
2. **Continuity** — hold that proof as a time-bounded trust session so the user doesn't sign on every message
3. **Control** — let your app gate sensitive actions with scoped step-up signatures

> **WalletWitness proves and reports. Your app decides what each trust level is allowed to do.**

---

## Trust States

| State | What it means |
|---|---|
| `anonymous` | No session, no proof |
| `authenticated_unverified` | App session exists, but no wallet proof (or proof expired) |
| `verified_identity` | Wallet ownership proven — time-bounded, address-bound |
| `verified_action` | Short-lived scoped grant for one specific sensitive action |

Trust only moves **up** via cryptographic signature — never from conversation context or session inference.

---

## Packages

| Package | What it contains |
|---|---|
| `@walletwitness/core` | Challenge issuance, signature verification, trust session lifecycle, action grants, chain validation |
| `@walletwitness/server` | Express middleware — session attach, challenge route, verify route, protect middleware with policy callback |
| `walletwitness-demo` | Runnable end-to-end reference flow |

---

## Quick Start

```bash
npm install
npm test
```

---

## Integration Example

```js
const express = require('express');
const {
  createWalletWitnessMiddleware,
  createProtectMiddleware,
} = require('@walletwitness/server');
const { trustSatisfiesRequirement } = require('@walletwitness/core');

const app = express();
app.use(express.json());

// 1. Mount the middleware
const walletWitness = createWalletWitnessMiddleware({
  appName: 'My App',
  expectedChainId: 8453,           // Base mainnet; change to match your chain
  resolveSubject(req) {
    // Return the authenticated user's ID from your existing session
    return req.user?.id || null;
  },
});

app.use(walletWitness.attachTrustSession); // attaches req.walletWitness.trust on every request
app.post('/wallet/challenge', walletWitness.challengeRoute);
app.post('/wallet/verify',    walletWitness.verifyRoute);

// 2. Protect a sensitive route with your own policy
app.delete('/data/:id', createProtectMiddleware({
  resolveAction(req) {
    return { kind: 'delete', scope: `data:${req.params.id}` };
  },
  policy({ trust, action }) {
    // Your policy decides what verified_identity or verified_action unlocks
    return {
      allow: trustSatisfiesRequirement(trust, 'verified_action', action),
      reason: 'A wallet-signed step-up is required to delete data.',
      requiredTrust: 'verified_action',
    };
  },
}), (req, res) => {
  res.json({ deleted: req.params.id });
});
```

### What happens on the client

The flow is: **request challenge → sign with wallet → submit signature → get trust session**

```
POST /wallet/challenge  { address, chainId }
→ { challengeId, challenge: { message, nonce, expiresAt } }

// User signs challenge.message with their wallet (MetaMask, WalletConnect, etc.)

POST /wallet/verify     { challengeId, message, signature }
→ { trust: { state: 'verified_identity', address, chainId, expiresAt } }
```

For a scoped step-up (to reach `verified_action`), repeat the same flow with `purpose: 'verify-action'` and `action: { kind, scope }`.

---

## Reading Trust State

At any point, `req.walletWitness.trust` gives you the current trust state:

```js
app.get('/profile', (req, res) => {
  const { trust } = req.walletWitness;

  if (trust.state === 'verified_identity') {
    // trust.address — verified EVM address
    // trust.chainId — verified chain
    // trust.expiresAt — when the session expires
  }
});
```

---

## Running the Demo

```bash
npm run demo
```

The demo walks through the full flow in a single process: anonymous → verified identity → blocked sensitive route → step-up → route succeeds.

---

## Design Notes

- **Chain mismatch is an explicit error**, not a silent fallback. Base (chainId 8453) is the default; configure `expectedChainId` for other chains.
- **Challenges are single-use.** Replay attacks are blocked at the store level.
- **Nonces are cryptographically random** (18 bytes, base64url).
- **Trust sessions default to 24h.** Verified action grants default to 5 minutes. Both are configurable.
- **Memory stores are included** for development and testing. Bring your own Redis/Postgres adapter for production.
- **Extracted from production.** The challenge/sign/verify flow and trust session model have been running in a live AI agent system. This is not a prototype.

---

## Spec

Full threat model, trust contract, package architecture, and MVP boundary: [`SPEC.md`](./SPEC.md)
