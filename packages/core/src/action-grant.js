const { normalizeAddress } = require('./chain');

const DEFAULT_VERIFIED_ACTION_TTL_MS = 60 * 60 * 1000;

function makeError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details && typeof details === 'object') {
    error.details = details;
  }
  return error;
}

function normalizeScope(scope) {
  const normalized = String(scope || '').replace(/\s+/g, ' ').trim();
  if (!normalized) {
    throw makeError('INVALID_ACTION_SCOPE', 'Verified action grants require a non-empty scope.');
  }
  return normalized.slice(0, 200);
}

function normalizeDuration(ttlMs, fallback = DEFAULT_VERIFIED_ACTION_TTL_MS) {
  const normalized = Math.trunc(Number(ttlMs));
  if (Number.isFinite(normalized) && normalized > 0) {
    return normalized;
  }
  return fallback;
}

function issueVerifiedActionGrant({
  address,
  scope,
  ttlMs = DEFAULT_VERIFIED_ACTION_TTL_MS,
  now = Date.now(),
}) {
  const issuedAt = Math.trunc(Number(now) || Date.now());
  const expiresAt = issuedAt + normalizeDuration(ttlMs);

  return {
    scope: normalizeScope(scope),
    address: normalizeAddress(address),
    issuedAt,
    expiresAt,
  };
}

function isVerifiedActionGrantActive(grant, {
  address,
  now = Date.now(),
  scope,
} = {}) {
  if (!grant || typeof grant !== 'object') {
    return false;
  }

  const expiresAt = Math.trunc(Number(grant.expiresAt));
  if (!Number.isFinite(expiresAt) || expiresAt <= Math.trunc(Number(now) || Date.now())) {
    return false;
  }

  if (address && normalizeAddress(address) !== normalizeAddress(grant.address)) {
    return false;
  }

  if (scope && normalizeScope(scope) !== normalizeScope(grant.scope)) {
    return false;
  }

  return true;
}

module.exports = {
  DEFAULT_VERIFIED_ACTION_TTL_MS,
  isVerifiedActionGrantActive,
  issueVerifiedActionGrant,
};
