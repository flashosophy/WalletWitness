'use strict';

const express = require('express');
const path = require('path');
const {
  createWalletWitnessMiddleware,
  createProtectMiddleware,
  createMemoryTrustSessionStore,
} = require('../packages/server');
const {
  trustSatisfiesRequirement,
  issueChallenge,
  verifyChallengeResponse,
  createTrustSession,
  createMemoryChallengeStore,
  evaluateTrustSession,
} = require('../packages/core');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Shared stores (in-memory for demo; swap for Redis/Postgres in production)
const challengeStore = createMemoryChallengeStore();
const trustSessionStore = createMemoryTrustSessionStore();
const SESSION_HEADER = 'x-walletwitness-session';

const walletWitness = createWalletWitnessMiddleware({
  appName: 'WalletWitness Demo',
  expectedChainId: 8453,
  challengeStore,
  trustSessionStore,
  resolveSubject(req) {
    return req.headers['x-demo-user'] || 'demo-user';
  },
});

app.use(walletWitness.attachTrustSession);

// --- Custom challenge route that accepts a client-chosen TTL ---
app.post('/wallet/challenge', async (req, res) => {
  try {
    const body = req.body || {};

    if (String(body.purpose || '').trim().toLowerCase() === 'verify-action') {
      return walletWitness.challengeRoute(req, res);
    }

    const { sessionId, subject, trust } = req.walletWitness;

    if (!sessionId || !subject) {
      return res.status(401).json({ error: 'Authenticated session required.' });
    }

    // TTL from client (ms). Validated server-side against allowed values.
    const ALLOWED_TTLS = [
      10 * 60 * 1000,       // 10 min
      60 * 60 * 1000,       // 1 hour
      8 * 60 * 60 * 1000,   // 8 hours
      12 * 60 * 60 * 1000,  // 12 hours
      24 * 60 * 60 * 1000,  // 24 hours
    ];
    const DEFAULT_TTL = 60 * 60 * 1000; // 1 hour
    const requestedTtl = Number(body.trustSessionTtlMs) || DEFAULT_TTL;
    const trustSessionTtlMs = ALLOWED_TTLS.includes(requestedTtl) ? requestedTtl : DEFAULT_TTL;

    const origin = req.headers.origin || `http://${req.headers.host || 'localhost'}`;
    let domain = 'localhost';
    try { domain = new URL(origin).host; } catch (_) {}

    const challenge = await issueChallenge({
      address: body.address,
      chainId: body.chainId ?? 8453,
      expectedChainId: 8453,
      appName: 'WalletWitness Demo',
      sessionId,
      subject,
      domain,
      uri: origin,
      store: challengeStore,
      verificationTtlMs: trustSessionTtlMs,
    });

    res.setHeader(SESSION_HEADER, sessionId);
    res.json({ challenge, sessionId, trust });
  } catch (err) {
    res.status(400).json({ error: { code: err.code || 'ERROR', message: err.message } });
  }
});

// --- Verify route (delegate to middleware) ---
app.post('/wallet/verify', walletWitness.verifyRoute);

// --- Trust state ---
app.get('/wallet/trust', (req, res) => {
  res.json({ trust: req.walletWitness.trust });
});

// --- Protected routes ---

app.get('/protected/identity', createProtectMiddleware({
  policy({ trust }) {
    return {
      allow: trustSatisfiesRequirement(trust, 'verified_identity'),
      reason: 'Wallet verification required.',
      requiredTrust: 'verified_identity',
    };
  },
}), (req, res) => {
  res.json({
    ok: true,
    message: `Identity confirmed. Wallet: ${req.walletWitness.trust.address}`,
    trust: req.walletWitness.trust,
  });
});

app.post('/protected/action', createProtectMiddleware({
  resolveAction() {
    return { kind: 'delete', scope: 'demo:delete' };
  },
  policy({ trust, action }) {
    return {
      allow: trustSatisfiesRequirement(trust, 'verified_action', action),
      reason: 'A scoped wallet step-up is required for this action.',
      requiredTrust: 'verified_action',
    };
  },
}), (req, res) => {
  res.json({
    ok: true,
    message: 'Sensitive action authorized.',
    trust: req.walletWitness.trust,
  });
});

const PORT = Number(process.env.PORT || 4747);
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, HOST, () => {
  console.log(`WalletWitness web demo running at http://${HOST}:${PORT}`);
});
