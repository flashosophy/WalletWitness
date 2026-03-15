const test = require('node:test');
const assert = require('node:assert/strict');

const { privateKeyToAccount } = require('viem/accounts');

const {
  DEFAULT_CHAIN_ID,
  assertExpectedChainId,
  attachActionGrant,
  createAuthenticatedTrustSession,
  createMemoryChallengeStore,
  createTrustSession,
  evaluateTrustSession,
  issueChallenge,
  issueVerifiedActionGrant,
  trustSatisfiesRequirement,
  verifyChallengeResponse,
} = require('../index');

const account = privateKeyToAccount(
  '0x59c6995e998f97a5a0044976f1d81f4edc7d4b6ed7f42fb178cdb5f7f8b3d1cf'
);

test('chain normalization rejects an explicit mismatch', () => {
  assert.equal(assertExpectedChainId('0x2105', DEFAULT_CHAIN_ID), 8453);
  assert.throws(
    () => assertExpectedChainId(1, DEFAULT_CHAIN_ID),
    (error) => error && error.code === 'CHAIN_MISMATCH'
  );
});

test('challenge issuance and verification create a verified identity session', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    sessionId: 'sess_identity',
    subject: 'Jun',
    appName: 'WalletWitness Demo',
  });

  assert.match(challenge.message, /Sign in to WalletWitness Demo\./i);
  assert.equal(challenge.message.includes('Request ID:'), false);
  assert.equal(challenge.message.includes('Resources:'), false);
  const signature = await account.signMessage({ message: challenge.message });
  const { verificationRecord } = await verifyChallengeResponse({
    store,
    challengeId: challenge.challengeId,
    message: challenge.message,
    signature,
    expectedChainId: DEFAULT_CHAIN_ID,
  });

  const trust = createTrustSession({ verificationRecord });

  assert.equal(trust.state, 'verified_identity');
  assert.equal(trust.address, account.address.toLowerCase());
  assert.equal(trust.chainId, DEFAULT_CHAIN_ID);
  assert.ok(trust.expiresAt > trust.verifiedAt);
});

test('request IDs and resources stay opt-in for special integrations', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    requestId: 'req_walletwitness_demo',
    resources: [
      'urn:walletwitness:purpose:verify-session',
      'urn:walletwitness:context:eva-core',
    ],
  });

  assert.equal(challenge.message.includes('Request ID: req_walletwitness_demo'), true);
  assert.equal(challenge.message.includes('Resources:'), true);
  assert.deepEqual(challenge.resources, [
    'urn:walletwitness:purpose:verify-session',
    'urn:walletwitness:context:eva-core',
  ]);
});

test('step-up challenges keep the action scope in plain language without auto resources', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    appName: 'WalletWitness Demo',
    purpose: 'verify-action',
    action: {
      kind: 'delete',
      scope: 'demo:dangerous-delete',
    },
    verificationTtlMs: 5 * 60 * 1000,
  });

  assert.match(challenge.message, /Approve action for WalletWitness Demo: demo:dangerous-delete\./i);
  assert.equal(challenge.message.includes('Request ID:'), false);
  assert.equal(challenge.message.includes('Resources:'), false);
});

test('challenge replay is blocked after a successful verification', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    sessionId: 'sess_replay',
    subject: 'Jun',
  });
  const signature = await account.signMessage({ message: challenge.message });

  await verifyChallengeResponse({
    store,
    challengeId: challenge.challengeId,
    message: challenge.message,
    signature,
    expectedChainId: DEFAULT_CHAIN_ID,
  });

  await assert.rejects(
    verifyChallengeResponse({
      store,
      challengeId: challenge.challengeId,
      message: challenge.message,
      signature,
      expectedChainId: DEFAULT_CHAIN_ID,
    }),
    (error) => error && error.code === 'CHALLENGE_USED'
  );
});

test('challenge verification is bound to the issuing session', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    sessionId: 'sess_origin',
    subject: 'Jun',
  });
  const signature = await account.signMessage({ message: challenge.message });

  await assert.rejects(
    verifyChallengeResponse({
      store,
      challengeId: challenge.challengeId,
      message: challenge.message,
      signature,
      sessionId: 'sess_other',
      expectedChainId: DEFAULT_CHAIN_ID,
    }),
    (error) => error && error.code === 'SESSION_MISMATCH'
  );

  const { verificationRecord } = await verifyChallengeResponse({
    store,
    challengeId: challenge.challengeId,
    message: challenge.message,
    signature,
    sessionId: 'sess_origin',
    expectedChainId: DEFAULT_CHAIN_ID,
  });

  assert.equal(verificationRecord.address, account.address.toLowerCase());
});

test('message mismatch and chain mismatch do not silently fall back', async () => {
  const store = createMemoryChallengeStore();
  const challenge = await issueChallenge({
    store,
    address: account.address,
    chainId: DEFAULT_CHAIN_ID,
    sessionId: 'sess_strict',
    subject: 'Jun',
  });
  const signature = await account.signMessage({ message: challenge.message });

  await assert.rejects(
    verifyChallengeResponse({
      store,
      challengeId: challenge.challengeId,
      message: `${challenge.message}\nextra`,
      signature,
      expectedChainId: DEFAULT_CHAIN_ID,
    }),
    (error) => error && error.code === 'MESSAGE_MISMATCH'
  );

  await assert.rejects(
    verifyChallengeResponse({
      store,
      challengeId: challenge.challengeId,
      message: challenge.message,
      signature,
      expectedChainId: 1,
    }),
    (error) => error && error.code === 'CHAIN_MISMATCH'
  );

  const { verificationRecord } = await verifyChallengeResponse({
    store,
    challengeId: challenge.challengeId,
    message: challenge.message,
    signature,
    expectedChainId: DEFAULT_CHAIN_ID,
  });

  assert.equal(verificationRecord.chainId, DEFAULT_CHAIN_ID);
});

test('verified action grants are scoped, time-bounded, and downgrade cleanly', () => {
  const verifiedAt = 10_000;
  const trust = createTrustSession({
    verificationRecord: {
      address: account.address,
      chainId: DEFAULT_CHAIN_ID,
      signature: '0x1234',
      challenge: {
        nonce: 'nonce',
        issuedAt: verifiedAt - 100,
        expiresAt: verifiedAt + 100,
      },
      verifiedAt,
    },
    ttlMs: 1_000,
  });
  const grant = issueVerifiedActionGrant({
    address: account.address,
    scope: 'dangerous:delete',
    ttlMs: 50,
    now: verifiedAt,
  });
  const steppedUp = attachActionGrant(trust, grant, { now: verifiedAt });

  assert.equal(steppedUp.state, 'verified_action');
  assert.equal(
    trustSatisfiesRequirement(steppedUp, 'verified_action', { scope: 'dangerous:delete' }, { now: verifiedAt + 10 }),
    true
  );
  assert.equal(
    trustSatisfiesRequirement(steppedUp, 'verified_action', { scope: 'dangerous:rotate' }, { now: verifiedAt + 10 }),
    false
  );

  const afterGrantExpiry = evaluateTrustSession(steppedUp, { now: verifiedAt + 60 });
  assert.equal(afterGrantExpiry.state, 'verified_identity');
  assert.equal(afterGrantExpiry.actionGrant, undefined);

  const afterSessionExpiry = evaluateTrustSession(steppedUp, { now: verifiedAt + 1_100 });
  assert.deepEqual(afterSessionExpiry, createAuthenticatedTrustSession());
});
