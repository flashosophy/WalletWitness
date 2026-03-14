const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const express = require('express');
const { privateKeyToAccount } = require('viem/accounts');

function loadCore() {
  try {
    return require('@walletwitness/core');
  } catch (_error) {
    return require('../../core');
  }
}

function loadServer() {
  try {
    return require('@walletwitness/server');
  } catch (_error) {
    return require('..');
  }
}

const { trustSatisfiesRequirement } = loadCore();
const {
  createWalletWitnessMiddleware,
  createProtectMiddleware,
} = loadServer();

const account = privateKeyToAccount(
  '0x59c6995e998f97a5a0044976f1d81f4edc7d4b6ed7f42fb178cdb5f7f8b3d1cf'
);

async function createRuntime() {
  const app = express();
  app.use(express.json());

  const walletWitness = createWalletWitnessMiddleware({
    appName: 'WalletWitness Demo',
    expectedChainId: 8453,
    trustSessionTtlMs: 1_000,
    verifiedActionTtlMs: 30,
    resolveSubject(req) {
      return String(req.headers['x-demo-user'] || '').trim() || null;
    },
  });

  const readPolicy = createProtectMiddleware({
    policy({ trust }) {
      return {
        allow: trustSatisfiesRequirement(trust, 'verified_identity'),
        reason: 'Verified identity required.',
        requiredTrust: 'verified_identity',
      };
    },
  });

  const deletePolicy = createProtectMiddleware({
    resolveAction() {
      return {
        kind: 'delete',
        scope: 'demo:dangerous-delete',
      };
    },
    policy({ trust, action }) {
      return {
        allow: trustSatisfiesRequirement(trust, 'verified_action', action),
        reason: 'Verified action required for dangerous delete.',
        requiredTrust: 'verified_action',
      };
    },
  });

  app.use(walletWitness.attachTrustSession);
  app.get('/session', (req, res) => {
    res.json({
      sessionId: req.walletWitness.sessionId,
      trust: req.walletWitness.trust,
    });
  });
  app.post('/wallet/challenge', walletWitness.challengeRoute);
  app.post('/wallet/verify', walletWitness.verifyRoute);
  app.post('/notes', readPolicy, (_req, res) => {
    res.json({ ok: true, route: 'notes' });
  });
  app.post('/dangerous', deletePolicy, (_req, res) => {
    res.json({ ok: true, route: 'dangerous' });
  });

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  const host = typeof address === 'object' && address?.address && address.address !== '::'
    ? address.address
    : '127.0.0.1';
  const baseUrl = `http://${host}:${address.port}`;

  return {
    baseUrl,
    close: async () => {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function sessionHeaders(userId, sessionId) {
  return {
    'Content-Type': 'application/json',
    'x-demo-user': userId,
    ...(sessionId ? { 'x-walletwitness-session': sessionId } : {}),
  };
}

test('middleware supports verify, gate, step-up, and expiry downgrade', async () => {
  const runtime = await createRuntime();

  try {
    const anonymousSession = await fetch(`${runtime.baseUrl}/session`);
    assert.equal(anonymousSession.status, 200);
    const anonymousPayload = await anonymousSession.json();
    assert.equal(anonymousPayload.trust.state, 'anonymous');

    const unauthenticatedDelete = await fetch(`${runtime.baseUrl}/dangerous`, {
      method: 'POST',
      headers: sessionHeaders('user-jun'),
    });
    assert.equal(unauthenticatedDelete.status, 403);
    const unauthenticatedDeletePayload = await unauthenticatedDelete.json();
    assert.equal(unauthenticatedDeletePayload.requiredTrust, 'verified_action');

    const badChainChallenge = await fetch(`${runtime.baseUrl}/wallet/challenge`, {
      method: 'POST',
      headers: sessionHeaders('user-jun'),
      body: JSON.stringify({
        address: account.address,
        chainId: 1,
      }),
    });
    assert.equal(badChainChallenge.status, 409);
    const badChainPayload = await badChainChallenge.json();
    assert.equal(badChainPayload.error.code, 'chain_mismatch');

    const challengeResponse = await fetch(`${runtime.baseUrl}/wallet/challenge`, {
      method: 'POST',
      headers: sessionHeaders('user-jun'),
      body: JSON.stringify({
        address: account.address,
        chainId: 8453,
      }),
    });
    assert.equal(challengeResponse.status, 200);
    const sessionId = challengeResponse.headers.get('x-walletwitness-session');
    assert.ok(sessionId);
    const challengePayload = await challengeResponse.json();
    assert.equal(challengePayload.trust.state, 'authenticated_unverified');

    const signature = await account.signMessage({
      message: challengePayload.challenge.message,
    });
    const verifyResponse = await fetch(`${runtime.baseUrl}/wallet/verify`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
      body: JSON.stringify({
        challengeId: challengePayload.challenge.challengeId,
        message: challengePayload.challenge.message,
        signature,
      }),
    });
    assert.equal(verifyResponse.status, 200);
    const verifyPayload = await verifyResponse.json();
    assert.equal(verifyPayload.trust.state, 'verified_identity');
    assert.equal(verifyPayload.trust.address, account.address.toLowerCase());

    const notesResponse = await fetch(`${runtime.baseUrl}/notes`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
    });
    assert.equal(notesResponse.status, 200);

    const blockedDangerousResponse = await fetch(`${runtime.baseUrl}/dangerous`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
    });
    assert.equal(blockedDangerousResponse.status, 403);
    const blockedDangerousPayload = await blockedDangerousResponse.json();
    assert.equal(blockedDangerousPayload.requiredTrust, 'verified_action');

    const stepUpChallengeResponse = await fetch(`${runtime.baseUrl}/wallet/challenge`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
      body: JSON.stringify({
        purpose: 'verify-action',
        action: {
          kind: 'delete',
          scope: 'demo:dangerous-delete',
        },
      }),
    });
    assert.equal(stepUpChallengeResponse.status, 200);
    const stepUpChallengePayload = await stepUpChallengeResponse.json();
    assert.match(stepUpChallengePayload.challenge.message, /Authorize this WalletWitness Demo action/i);

    const stepUpSignature = await account.signMessage({
      message: stepUpChallengePayload.challenge.message,
    });
    const stepUpVerifyResponse = await fetch(`${runtime.baseUrl}/wallet/verify`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
      body: JSON.stringify({
        challengeId: stepUpChallengePayload.challenge.challengeId,
        message: stepUpChallengePayload.challenge.message,
        signature: stepUpSignature,
      }),
    });
    assert.equal(stepUpVerifyResponse.status, 200);
    const stepUpVerifyPayload = await stepUpVerifyResponse.json();
    assert.equal(stepUpVerifyPayload.trust.state, 'verified_action');
    assert.equal(stepUpVerifyPayload.trust.actionGrant.scope, 'demo:dangerous-delete');

    const allowedDangerousResponse = await fetch(`${runtime.baseUrl}/dangerous`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
    });
    assert.equal(allowedDangerousResponse.status, 200);

    await new Promise((resolve) => setTimeout(resolve, 60));

    const expiredSessionResponse = await fetch(`${runtime.baseUrl}/session`, {
      headers: sessionHeaders('user-jun', sessionId),
    });
    assert.equal(expiredSessionResponse.status, 200);
    const expiredSessionPayload = await expiredSessionResponse.json();
    assert.equal(expiredSessionPayload.trust.state, 'verified_identity');

    const expiredDangerousResponse = await fetch(`${runtime.baseUrl}/dangerous`, {
      method: 'POST',
      headers: sessionHeaders('user-jun', sessionId),
    });
    assert.equal(expiredDangerousResponse.status, 403);
  } finally {
    await runtime.close();
  }
});
