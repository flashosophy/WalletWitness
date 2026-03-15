const { randomBytes, randomUUID } = require('node:crypto');

const {
  DEFAULT_CHAIN_ID,
  assertExpectedChainId,
  normalizeAddress,
  normalizeChainId,
} = require('./chain');

const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const VERIFY_SESSION_PURPOSE = 'verify-session';
const VERIFY_ACTION_PURPOSE = 'verify-action';

function makeError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details && typeof details === 'object') {
    error.details = details;
  }
  return error;
}

function toTimestamp(value, fallback = Date.now()) {
  const timestamp = Number(value);
  if (Number.isFinite(timestamp)) {
    return Math.trunc(timestamp);
  }
  return Math.trunc(fallback);
}

function addMs(value, deltaMs) {
  return toTimestamp(value) + Math.max(1, Math.trunc(Number(deltaMs) || 0));
}

function createNonce(size = 18) {
  return randomBytes(size).toString('base64url');
}

function normalizeChallengePurpose(value) {
  return String(value || VERIFY_SESSION_PURPOSE).trim().toLowerCase() === VERIFY_ACTION_PURPOSE
    ? VERIFY_ACTION_PURPOSE
    : VERIFY_SESSION_PURPOSE;
}

function normalizeContext(value) {
  const normalized = String(value || '').replace(/\s+/g, ' ').trim();
  return normalized ? normalized.slice(0, 200) : undefined;
}

function normalizeOptionalString(value) {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeResources(resources) {
  if (!Array.isArray(resources)) return [];

  const normalized = [];
  const seen = new Set();

  for (const resource of resources) {
    const value = String(resource || '').replace(/\s+/g, ' ').trim();
    if (!value) continue;

    const trimmed = value.slice(0, 500);
    if (seen.has(trimmed)) continue;

    seen.add(trimmed);
    normalized.push(trimmed);
  }

  return normalized;
}

function normalizeAction(action = null) {
  if (!action || typeof action !== 'object') return null;

  const kind = String(action.kind || '').trim().toLowerCase();
  const scope = String(action.scope || '').replace(/\s+/g, ' ').trim();

  if (!scope) {
    throw makeError(
      'INVALID_ACTION_SCOPE',
      'Verified action challenges require an action scope.'
    );
  }

  return {
    kind: kind || 'action',
    scope: scope.slice(0, 200),
  };
}

function formatDuration(ms) {
  const normalized = Math.max(60 * 1000, Math.trunc(Number(ms) || 0));
  const minutes = normalized / (60 * 1000);

  if (minutes % 60 === 0) {
    const hours = minutes / 60;
    return hours === 1 ? '1 hour' : `${hours} hours`;
  }

  return minutes === 1 ? '1 minute' : `${minutes} minutes`;
}

function buildChallengeStatement({
  action,
  appName,
  purpose,
  verificationTtlMs,
}) {
  if (purpose === VERIFY_ACTION_PURPOSE) {
    const scope = action?.scope || 'sensitive action';
    return `Approve action for ${appName}: ${scope}. Expires in ${formatDuration(verificationTtlMs)}.`;
  }

  return `Sign in to ${appName}.`;
}

function buildChallengeMessage({
  address,
  chainId,
  domain,
  expiresAt,
  issuedAt,
  nonce,
  requestId,
  resources = [],
  statement,
  uri,
}) {
  const lines = [
    `${domain} wants you to sign in with your Ethereum account:`,
    address,
    '',
    statement,
    '',
    `URI: ${uri}`,
    'Version: 1',
    `Chain ID: ${chainId}`,
    `Nonce: ${nonce}`,
    `Issued At: ${new Date(issuedAt).toISOString()}`,
    `Expiration Time: ${new Date(expiresAt).toISOString()}`,
  ];

  if (requestId) {
    lines.push(`Request ID: ${requestId}`);
  }

  if (resources.length > 0) {
    lines.push('Resources:');
    for (const resource of resources) {
      lines.push(`- ${resource}`);
    }
  }

  return lines.join('\n');
}

function createMemoryChallengeStore() {
  const challenges = new Map();

  return {
    async save(challenge) {
      challenges.set(challenge.challengeId, { ...challenge });
      return { ...challenge };
    },

    async get(challengeId) {
      const challenge = challenges.get(String(challengeId || '').trim());
      return challenge ? { ...challenge } : null;
    },

    async consume(challengeId, { message, now = Date.now() } = {}) {
      const normalizedId = String(challengeId || '').trim();
      const challenge = challenges.get(normalizedId);

      if (!challenge) {
        return null;
      }

      if (challenge.usedAt) {
        throw makeError('CHALLENGE_USED', 'Challenge has already been used.');
      }

      const currentTime = toTimestamp(now);
      if (challenge.expiresAt <= currentTime) {
        throw makeError('CHALLENGE_EXPIRED', 'Challenge has expired.');
      }

      if (typeof message === 'string' && message !== challenge.message) {
        throw makeError('MESSAGE_MISMATCH', 'Signed message does not match the issued challenge.');
      }

      const consumed = {
        ...challenge,
        usedAt: currentTime,
      };

      challenges.set(normalizedId, consumed);
      return { ...consumed };
    },

    async purgeExpired(now = Date.now()) {
      const currentTime = toTimestamp(now);
      let removed = 0;

      for (const [challengeId, challenge] of challenges.entries()) {
        if (challenge.expiresAt <= currentTime || challenge.usedAt) {
          challenges.delete(challengeId);
          removed += 1;
        }
      }

      return removed;
    },
  };
}

async function readChallenge({
  challengeId,
  message,
  now = Date.now(),
  sessionId,
  store,
}) {
  if (!store || typeof store.get !== 'function') {
    throw new Error('Challenge store must expose a get(challengeId) method.');
  }

  const challenge = await store.get(challengeId);
  if (!challenge) {
    throw makeError('CHALLENGE_NOT_FOUND', 'Challenge was not found.');
  }

  if (challenge.usedAt) {
    throw makeError('CHALLENGE_USED', 'Challenge has already been used.');
  }

  if (challenge.expiresAt <= toTimestamp(now)) {
    throw makeError('CHALLENGE_EXPIRED', 'Challenge has expired.');
  }

  if (typeof message === 'string' && message !== challenge.message) {
    throw makeError('MESSAGE_MISMATCH', 'Signed message does not match the issued challenge.');
  }

  const expectedSessionId = normalizeOptionalString(sessionId);
  if (expectedSessionId && challenge.sessionId !== expectedSessionId) {
    throw makeError(
      'SESSION_MISMATCH',
      'Challenge was issued for a different host session.',
      {
        actualSessionId: challenge.sessionId || null,
        expectedSessionId,
      }
    );
  }

  return challenge;
}

async function consumeChallenge({
  challengeId,
  message,
  now = Date.now(),
  sessionId,
  store,
}) {
  if (!store || typeof store.consume !== 'function') {
    throw new Error('Challenge store must expose a consume(challengeId, options) method.');
  }

  await readChallenge({
    challengeId,
    message,
    now,
    sessionId,
    store,
  });

  const challenge = await store.consume(challengeId, { message, now });
  if (!challenge) {
    throw makeError('CHALLENGE_NOT_FOUND', 'Challenge was not found.');
  }

  return challenge;
}

async function issueChallenge({
  action = null,
  address,
  appName = 'WalletWitness',
  challengeTtlMs = DEFAULT_CHALLENGE_TTL_MS,
  chainId = DEFAULT_CHAIN_ID,
  context,
  domain = 'walletwitness.local',
  expectedChainId = chainId,
  now = Date.now(),
  purpose = VERIFY_SESSION_PURPOSE,
  requestId,
  resources,
  sessionId = '',
  store,
  subject = 'User',
  uri = 'http://localhost',
  verificationTtlMs = 24 * 60 * 60 * 1000,
} = {}) {
  if (!store || typeof store.save !== 'function') {
    throw new Error('Challenge store must expose a save(challenge) method.');
  }

  const normalizedPurpose = normalizeChallengePurpose(purpose);
  const normalizedAddress = normalizeAddress(address);
  const normalizedChainId = normalizeChainId(chainId);
  assertExpectedChainId(normalizedChainId, expectedChainId);

  const issuedAt = toTimestamp(now);
  const expiresAt = addMs(issuedAt, challengeTtlMs);
  const nonce = createNonce();
  const normalizedAction = normalizedPurpose === VERIFY_ACTION_PURPOSE
    ? normalizeAction(action)
    : null;
  const normalizedContext = normalizeContext(context);
  const normalizedRequestId = normalizeOptionalString(requestId);
  const normalizedResources = normalizeResources(resources);
  const statement = buildChallengeStatement({
    action: normalizedAction,
    appName: String(appName || 'WalletWitness').trim() || 'WalletWitness',
    purpose: normalizedPurpose,
    verificationTtlMs,
  });
  const message = buildChallengeMessage({
    address: normalizeAddress(address, { checksum: true }),
    chainId: normalizedChainId,
    domain: String(domain || 'walletwitness.local').trim() || 'walletwitness.local',
    expiresAt,
    issuedAt,
    nonce,
    requestId: normalizedRequestId,
    resources: normalizedResources,
    statement,
    uri: String(uri || 'http://localhost').trim() || 'http://localhost',
  });

  const challenge = {
    challengeId: `wchal_${randomUUID()}`,
    nonce,
    issuedAt,
    expiresAt,
    context: normalizedContext,
    address: normalizedAddress,
    chainId: normalizedChainId,
    purpose: normalizedPurpose,
    action: normalizedAction,
    sessionId: normalizeOptionalString(sessionId),
    ...(normalizedRequestId ? { requestId: normalizedRequestId } : {}),
    ...(normalizedResources.length > 0 ? { resources: normalizedResources } : {}),
    verificationTtlMs: Math.max(1, Math.trunc(Number(verificationTtlMs) || 0)),
    message,
    usedAt: null,
  };

  await store.save(challenge);
  return challenge;
}

module.exports = {
  DEFAULT_CHALLENGE_TTL_MS,
  VERIFY_ACTION_PURPOSE,
  VERIFY_SESSION_PURPOSE,
  buildChallengeMessage,
  consumeChallenge,
  createMemoryChallengeStore,
  createNonce,
  issueChallenge,
  normalizeChallengePurpose,
  readChallenge,
};
