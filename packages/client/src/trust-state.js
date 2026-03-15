const TRUST_STATES = new Set([
  'anonymous',
  'authenticated_unverified',
  'verified_identity',
  'verified_action',
]);

function normalizeOptionalString(value) {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeTimestamp(value) {
  const timestamp = Number(value);
  if (Number.isFinite(timestamp)) {
    return Math.trunc(timestamp);
  }
  return undefined;
}

function cloneTrustState(trust) {
  if (!trust || typeof trust !== 'object') {
    return { state: 'anonymous' };
  }

  return {
    ...trust,
    ...(trust.actionGrant ? { actionGrant: { ...trust.actionGrant } } : {}),
  };
}

function normalizeTrustState(trust) {
  if (!trust || typeof trust !== 'object') {
    return { state: 'anonymous' };
  }

  const state = normalizeOptionalString(trust.state);
  const normalizedState = state && TRUST_STATES.has(state)
    ? state
    : 'anonymous';

  const normalized = { state: normalizedState };

  const address = normalizeOptionalString(trust.address);
  if (address) normalized.address = address;

  const chainId = normalizeTimestamp(trust.chainId);
  if (chainId !== undefined) normalized.chainId = chainId;

  const verifiedAt = normalizeTimestamp(trust.verifiedAt);
  if (verifiedAt !== undefined) normalized.verifiedAt = verifiedAt;

  const expiresAt = normalizeTimestamp(trust.expiresAt);
  if (expiresAt !== undefined) normalized.expiresAt = expiresAt;

  if (trust.actionGrant && typeof trust.actionGrant === 'object') {
    const scope = normalizeOptionalString(trust.actionGrant.scope);
    const actionExpiresAt = normalizeTimestamp(trust.actionGrant.expiresAt);

    if (scope || actionExpiresAt !== undefined) {
      normalized.actionGrant = {
        ...(scope ? { scope } : {}),
        ...(actionExpiresAt !== undefined ? { expiresAt: actionExpiresAt } : {}),
      };
    }
  }

  return normalized;
}

function formatExpiry(expiresAt) {
  const timestamp = normalizeTimestamp(expiresAt);
  if (timestamp === undefined) return 'no expiry set';
  return new Date(timestamp).toISOString();
}

function describeTrustState(trust, { now = Date.now() } = {}) {
  const normalized = normalizeTrustState(trust);
  const currentTime = normalizeTimestamp(now) || Date.now();

  if (normalized.state === 'verified_action') {
    const scope = normalizeOptionalString(normalized.actionGrant?.scope) || 'sensitive action';
    const grantExpiresAt = normalizeTimestamp(normalized.actionGrant?.expiresAt);

    return {
      state: normalized.state,
      tone: 'elevated',
      label: 'Step-up verified',
      detail: grantExpiresAt && grantExpiresAt <= currentTime
        ? `Scoped action grant for ${scope} has expired.`
        : `Scoped action grant active for ${scope} until ${formatExpiry(grantExpiresAt)}.`,
    };
  }

  if (normalized.state === 'verified_identity') {
    return {
      state: normalized.state,
      tone: 'success',
      label: 'Verified identity',
      detail: `Wallet proof is active until ${formatExpiry(normalized.expiresAt)}.`,
    };
  }

  if (normalized.state === 'authenticated_unverified') {
    return {
      state: normalized.state,
      tone: 'warning',
      label: 'Signed in, unverified',
      detail: 'Host session is active, but wallet proof has not been completed yet.',
    };
  }

  return {
    state: 'anonymous',
    tone: 'neutral',
    label: 'Anonymous',
    detail: 'No authenticated host session or wallet proof is active.',
  };
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderTrustStatusBadge(trust, options = {}) {
  const summary = describeTrustState(trust, options);

  return [
    `<div class="walletwitness-trust walletwitness-trust--${escapeHtml(summary.tone)}" data-walletwitness-trust="${escapeHtml(summary.state)}">`,
    `  <strong>${escapeHtml(summary.label)}</strong>`,
    `  <span>${escapeHtml(summary.detail)}</span>`,
    '</div>',
  ].join('\n');
}

function createTrustStateStore(initialTrust) {
  let currentTrust = normalizeTrustState(initialTrust);
  const listeners = new Set();

  function snapshot() {
    return cloneTrustState(currentTrust);
  }

  function set(nextTrust) {
    currentTrust = normalizeTrustState(nextTrust);
    const nextSnapshot = snapshot();

    for (const listener of listeners) {
      listener(nextSnapshot);
    }

    return nextSnapshot;
  }

  return {
    get() {
      return snapshot();
    },

    set,

    subscribe(listener) {
      if (typeof listener !== 'function') {
        throw new Error('Trust store subscribers must be functions.');
      }

      listeners.add(listener);
      return () => listeners.delete(listener);
    },

    updateFromResponse(payload) {
      if (payload && typeof payload === 'object' && payload.trust) {
        return set(payload.trust);
      }

      return snapshot();
    },
  };
}

module.exports = {
  cloneTrustState,
  createTrustStateStore,
  describeTrustState,
  normalizeTrustState,
  renderTrustStatusBadge,
};
