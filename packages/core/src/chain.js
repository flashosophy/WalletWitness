const { getAddress, isAddress } = require('viem');

const DEFAULT_CHAIN_ID = 8453;

function makeError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details && typeof details === 'object') {
    error.details = details;
  }
  return error;
}

function normalizeChainId(value, { fallback = DEFAULT_CHAIN_ID, allowNull = false } = {}) {
  if (value === null || value === undefined || value === '') {
    if (allowNull) return null;
    return fallback;
  }

  const raw = String(value).trim();
  if (!raw) {
    if (allowNull) return null;
    return fallback;
  }

  const parsed = /^0x[0-9a-f]+$/i.test(raw)
    ? Number.parseInt(raw, 16)
    : Number.parseInt(raw, 10);

  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }

  if (allowNull) return null;
  throw makeError('INVALID_CHAIN_ID', 'Chain ID must be a positive integer.');
}

function assertExpectedChainId(chainId, expectedChainId = DEFAULT_CHAIN_ID) {
  const actual = normalizeChainId(chainId);
  const expected = normalizeChainId(expectedChainId, {
    fallback: null,
    allowNull: true,
  });

  if (expected !== null && actual !== expected) {
    throw makeError(
      'CHAIN_MISMATCH',
      `Expected chain ${expected}, received chain ${actual}.`,
      { expectedChainId: expected, actualChainId: actual }
    );
  }

  return actual;
}

function normalizeAddress(value, { checksum = false } = {}) {
  const raw = String(value || '').trim();
  if (!isAddress(raw)) {
    throw makeError('INVALID_ADDRESS', 'Wallet address must be a valid EVM address.');
  }

  const normalized = getAddress(raw);
  return checksum ? normalized : normalized.toLowerCase();
}

module.exports = {
  DEFAULT_CHAIN_ID,
  assertExpectedChainId,
  normalizeAddress,
  normalizeChainId,
};
