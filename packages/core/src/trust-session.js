const { isVerifiedActionGrantActive } = require('./action-grant');
const { normalizeAddress, normalizeChainId } = require('./chain');

const DEFAULT_TRUST_SESSION_TTL_MS = 24 * 60 * 60 * 1000;

const TRUST_LEVEL_ORDER = Object.freeze({
  anonymous: 0,
  authenticated_unverified: 1,
  verified_identity: 2,
  verified_action: 3,
});

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

function normalizeTrustState(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(TRUST_LEVEL_ORDER, normalized)
    ? normalized
    : 'anonymous';
}

function createAnonymousTrustSession() {
  return { state: 'anonymous' };
}

function createAuthenticatedTrustSession() {
  return { state: 'authenticated_unverified' };
}

function createTrustSession({
  ttlMs = DEFAULT_TRUST_SESSION_TTL_MS,
  verificationRecord,
}) {
  if (!verificationRecord || typeof verificationRecord !== 'object') {
    throw makeError('INVALID_VERIFICATION_RECORD', 'Verification record is required to create a trust session.');
  }

  const verifiedAt = toTimestamp(verificationRecord.verifiedAt);
  const expiresAt = verifiedAt + Math.max(1, Math.trunc(Number(ttlMs) || DEFAULT_TRUST_SESSION_TTL_MS));

  return {
    state: 'verified_identity',
    address: normalizeAddress(verificationRecord.address),
    chainId: normalizeChainId(verificationRecord.chainId),
    verifiedAt,
    expiresAt,
  };
}

function attachActionGrant(trustSession, actionGrant, { now = Date.now() } = {}) {
  const evaluated = evaluateTrustSession(trustSession, { now });
  if (evaluated.state !== 'verified_identity' && evaluated.state !== 'verified_action') {
    throw makeError(
      'TRUST_SESSION_NOT_VERIFIED',
      'Verified action grants require an active verified identity session.'
    );
  }

  if (!isVerifiedActionGrantActive(actionGrant, {
    address: evaluated.address,
    now,
  })) {
    throw makeError('INVALID_ACTION_GRANT', 'Verified action grant is missing, expired, or bound to a different wallet.');
  }

  return {
    ...evaluated,
    state: 'verified_action',
    actionGrant: {
      scope: String(actionGrant.scope),
      expiresAt: Math.trunc(Number(actionGrant.expiresAt)),
    },
  };
}

function evaluateTrustSession(trustSession, { now = Date.now() } = {}) {
  if (!trustSession || typeof trustSession !== 'object') {
    return createAnonymousTrustSession();
  }

  const currentTime = toTimestamp(now);
  const state = normalizeTrustState(trustSession.state);

  if (state === 'anonymous') {
    return createAnonymousTrustSession();
  }

  if (state === 'authenticated_unverified') {
    return createAuthenticatedTrustSession();
  }

  const expiresAt = toTimestamp(trustSession.expiresAt, NaN);
  if (!Number.isFinite(expiresAt) || expiresAt <= currentTime) {
    return createAuthenticatedTrustSession();
  }

  const verifiedSession = {
    state: 'verified_identity',
    address: normalizeAddress(trustSession.address),
    chainId: normalizeChainId(trustSession.chainId),
    verifiedAt: toTimestamp(trustSession.verifiedAt, currentTime),
    expiresAt,
  };

  if (!trustSession.actionGrant) {
    return verifiedSession;
  }

  const actionGrant = {
    scope: String(trustSession.actionGrant.scope || '').trim(),
    expiresAt: toTimestamp(trustSession.actionGrant.expiresAt, NaN),
    address: verifiedSession.address,
  };

  if (!isVerifiedActionGrantActive(actionGrant, {
    address: verifiedSession.address,
    now: currentTime,
  })) {
    return verifiedSession;
  }

  return {
    ...verifiedSession,
    state: 'verified_action',
    actionGrant: {
      scope: actionGrant.scope,
      expiresAt: actionGrant.expiresAt,
    },
  };
}

function compareTrustStates(left, right) {
  return TRUST_LEVEL_ORDER[normalizeTrustState(left)] - TRUST_LEVEL_ORDER[normalizeTrustState(right)];
}

function trustSatisfiesRequirement(trustSession, requiredTrust, action = null, { now = Date.now() } = {}) {
  const evaluated = evaluateTrustSession(trustSession, { now });
  const requiredState = normalizeTrustState(requiredTrust || 'authenticated_unverified');

  if (compareTrustStates(evaluated.state, requiredState) < 0) {
    return false;
  }

  if (requiredState !== 'verified_action') {
    return true;
  }

  const requiredScope = String(action?.scope || '').trim();
  if (!requiredScope) {
    return evaluated.state === 'verified_action';
  }

  return evaluated.actionGrant?.scope === requiredScope;
}

module.exports = {
  DEFAULT_TRUST_SESSION_TTL_MS,
  TRUST_LEVEL_ORDER,
  attachActionGrant,
  compareTrustStates,
  createAnonymousTrustSession,
  createAuthenticatedTrustSession,
  createTrustSession,
  evaluateTrustSession,
  trustSatisfiesRequirement,
};
