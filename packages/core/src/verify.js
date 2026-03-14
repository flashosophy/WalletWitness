const { recoverMessageAddress } = require('viem');

const { readChallenge, consumeChallenge } = require('./challenge');
const { assertExpectedChainId, normalizeAddress } = require('./chain');

function makeError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details && typeof details === 'object') {
    error.details = details;
  }
  return error;
}

function normalizeSignature(signature) {
  const normalized = String(signature || '').trim();
  if (!/^0x[0-9a-f]+$/i.test(normalized)) {
    throw makeError('INVALID_SIGNATURE', 'Signature must be a 0x-prefixed hex string.');
  }
  return normalized;
}

async function verifyPersonalSign({
  address,
  message,
  signature,
}) {
  const normalizedAddress = normalizeAddress(address);
  const normalizedSignature = normalizeSignature(signature);
  const recoveredAddress = await recoverMessageAddress({
    message,
    signature: normalizedSignature,
  });

  if (normalizeAddress(recoveredAddress) !== normalizedAddress) {
    throw makeError('SIGNATURE_MISMATCH', 'Signature did not recover the expected wallet address.');
  }

  return {
    address: normalizedAddress,
    recoveredAddress: normalizeAddress(recoveredAddress),
    signature: normalizedSignature,
  };
}

async function verifyChallengeResponse({
  challengeId,
  expectedChainId,
  message,
  now = Date.now(),
  signature,
  store,
}) {
  const challenge = await readChallenge({
    challengeId,
    message,
    now,
    store,
  });

  const chainId = assertExpectedChainId(challenge.chainId, expectedChainId ?? challenge.chainId);
  const proof = await verifyPersonalSign({
    address: challenge.address,
    message: challenge.message,
    signature,
  });

  await consumeChallenge({
    challengeId,
    message: challenge.message,
    now,
    store,
  });

  const verifiedAt = Math.trunc(Number(now) || Date.now());

  return {
    challenge,
    verificationRecord: {
      address: proof.address,
      chainId,
      signature: proof.signature,
      challenge: {
        nonce: challenge.nonce,
        issuedAt: challenge.issuedAt,
        expiresAt: challenge.expiresAt,
        ...(challenge.context ? { context: challenge.context } : {}),
      },
      verifiedAt,
    },
  };
}

module.exports = {
  verifyChallengeResponse,
  verifyPersonalSign,
};
