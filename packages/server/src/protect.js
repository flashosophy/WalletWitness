function loadCore() {
  try {
    return require('@walletwitness/core');
  } catch (_error) {
    return require('../../core');
  }
}

const { createAnonymousTrustSession } = loadCore();

function defaultActionFromRequest(req) {
  const method = String(req?.method || 'GET').trim().toLowerCase() || 'get';
  const path = String(req?.path || req?.originalUrl || '').trim();

  return {
    kind: method,
    ...(path ? { scope: path } : {}),
  };
}

function createProtectMiddleware({
  policy,
  resolveAction = defaultActionFromRequest,
} = {}) {
  if (typeof policy !== 'function') {
    throw new Error('createProtectMiddleware requires a policy callback.');
  }

  return function protectMiddleware(req, res, next) {
    const trust = req?.walletWitness?.trust || createAnonymousTrustSession();
    const action = typeof resolveAction === 'function'
      ? resolveAction(req)
      : undefined;
    const decision = policy({ trust, action }) || { allow: false };

    if (decision.allow === true) {
      return next();
    }

    const reason = String(decision.reason || 'Action denied by trust policy.').trim() || 'Action denied by trust policy.';
    const logEntry = {
      event: 'walletwitness:access_denied',
      at: new Date().toISOString(),
      trust_state: trust.state,
      address: trust.address || null,
      chain_id: trust.chainId || null,
      ...(action ? { action } : {}),
      reason,
      required_trust: decision.requiredTrust || null,
      session_id: req?.walletWitness?.sessionId || null,
    };
    console.warn('[WalletWitness] Access denied', JSON.stringify(logEntry));

    return res.status(403).json({
      error: reason,
      requiredTrust: decision.requiredTrust || null,
      trust,
      ...(action ? { action } : {}),
    });
  };
}

module.exports = {
  createProtectMiddleware,
};
