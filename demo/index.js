'use strict';

/**
 * WalletWitness Demo
 *
 * Minimal working integration showing:
 *   1. Challenge issuance
 *   2. Signature verification
 *   3. Trust session attach via middleware
 *   4. Policy-gated protected route
 *
 * In production, replace the in-memory stores with your own persistence layer.
 *
 * Run:
 *   npm install && node index.js
 *   Then hit http://localhost:3000
 */

const express = require('express');

// Load from workspace (monorepo) or installed package
function load(pkg) {
  try { return require(pkg); }
  catch (_) { return require(`../${pkg.replace('@walletwitness/', 'packages/')}`); }
}

const {
  createMemoryChallengeStore,
  createTrustSession,
  evaluateTrustSession,
} = load('@walletwitness/core');

const {
  createWalletWitnessMiddleware,
  createProtectMiddleware,
} = load('@walletwitness/server');

// ── In-memory stores (swap for DB/Redis in production) ──────────────────────

const challengeStore = createMemoryChallengeStore();

const trustSessionStore = (() => {
  const sessions = new Map();
  return {
    async get(key) { return sessions.get(key) ?? null; },
    async set(key, trust) { sessions.set(key, trust); return trust; },
    async delete(key) { sessions.delete(key); },
  };
})();

// ── Middleware ───────────────────────────────────────────────────────────────

const walletWitness = createWalletWitnessMiddleware({
  challengeStore,
  trustSessionStore,
  expectedChainId: 8453, // Base mainnet
  appName: 'WalletWitness Demo',
  domain: 'localhost',
  uri: 'http://localhost:3000',
  // Trust policy: verified_identity required for protected routes
  policy({ trust, action }) {
    if (trust.state === 'verified_identity' || trust.state === 'verified_action') {
      return { allow: true };
    }
    return {
      allow: false,
      reason: 'This route requires a verified wallet session.',
      requiredTrust: 'verified_identity',
    };
  },
});

const protect = createProtectMiddleware({
  policy({ trust }) {
    if (trust.state === 'verified_identity' || trust.state === 'verified_action') {
      return { allow: true };
    }
    return { allow: false, reason: 'Wallet verification required.', requiredTrust: 'verified_identity' };
  },
});

// ── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(walletWitness); // attaches req.walletWitness.trust on every request

// Public: request a challenge for a given wallet address
// POST /auth/challenge  { address: "0x...", chainId: 8453 }
// (handled by walletWitness middleware — this route is here for documentation)

// Public: verify a signed challenge and start a trust session
// POST /auth/verify  { challengeId, message, signature }
// (handled by walletWitness middleware)

// Public: check your current trust state
app.get('/me', (req, res) => {
  const trust = req.walletWitness?.trust ?? { state: 'anonymous' };
  res.json({ trust: evaluateTrustSession(trust) });
});

// Protected: requires verified wallet
app.get('/protected', protect, (req, res) => {
  const trust = evaluateTrustSession(req.walletWitness.trust);
  res.json({
    message: `Welcome, ${trust.address}. Your identity is cryptographically verified.`,
    trust,
  });
});

// Public: logout / revoke trust session
// POST /auth/revoke  (handled by walletWitness middleware)

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`WalletWitness demo running at http://localhost:${PORT}`);
  console.log('');
  console.log('Flow:');
  console.log('  1. POST /auth/challenge   { address, chainId }  → get challenge message');
  console.log('  2. Sign challenge.message with your wallet');
  console.log('  3. POST /auth/verify      { challengeId, message, signature }');
  console.log('  4. GET  /protected        (with x-walletwitness-session header)');
  console.log('  5. GET  /me               (shows your current trust state)');
});
