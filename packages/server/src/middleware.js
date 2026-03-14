const { randomUUID } = require('node:crypto');

function loadCore() {
  try {
    return require('@walletwitness/core');
  } catch (_error) {
    return require('../../core');
  }
}

const {
  DEFAULT_CHAIN_ID,
  DEFAULT_CHALLENGE_TTL_MS,
  DEFAULT_TRUST_SESSION_TTL_MS,
  DEFAULT_VERIFIED_ACTION_TTL_MS,
  VERIFY_ACTION_PURPOSE,
  createAnonymousTrustSession,
  createAuthenticatedTrustSession,
  createMemoryChallengeStore,
  createTrustSession,
  evaluateTrustSession,
  attachActionGrant,
  issueChallenge,
  issueVerifiedActionGrant,
  normalizeAddress,
  normalizeChainId,
  normalizeChallengePurpose,
  verifyChallengeResponse,
} = loadCore();

const DEFAULT_SESSION_HEADER = 'x-walletwitness-session';

function makeError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details && typeof details === 'object') {
    error.details = details;
  }
  return error;
}

function cloneTrustSession(trust) {
  if (!trust || typeof trust !== 'object') return null;
  return {
    ...trust,
    ...(trust.actionGrant ? { actionGrant: { ...trust.actionGrant } } : {}),
  };
}

function createMemoryTrustSessionStore() {
  const sessions = new Map();

  return {
    async get(storageKey) {
      const entry = sessions.get(String(storageKey || '').trim());
      return entry ? cloneTrustSession(entry) : null;
    },

    async set(storageKey, trust) {
      const normalizedKey = String(storageKey || '').trim();
      if (!normalizedKey) {
        throw new Error('Trust session store key is required.');
      }

      const cloned = cloneTrustSession(trust);
      sessions.set(normalizedKey, cloned);
      return cloneTrustSession(cloned);
    },

    async delete(storageKey) {
      sessions.delete(String(storageKey || '').trim());
    },
  };
}

function mapErrorCode(code) {
  return String(code || 'INTERNAL_ERROR').trim().toLowerCase();
}

function mapErrorStatus(error) {
  const code = String(error?.code || '').trim();

  if (code === 'CHAIN_MISMATCH' || code === 'IDENTITY_MISMATCH') return 409;
  if (code === 'CHALLENGE_NOT_FOUND') return 404;
  if (code === 'TRUST_SESSION_NOT_VERIFIED') return 403;
  if ([
    'INVALID_ADDRESS',
    'INVALID_ACTION_SCOPE',
    'INVALID_CHAIN_ID',
    'INVALID_SIGNATURE',
    'MESSAGE_MISMATCH',
    'SIGNATURE_MISMATCH',
    'CHALLENGE_EXPIRED',
    'CHALLENGE_USED',
  ].includes(code)) {
    return 400;
  }

  return 500;
}

function buildErrorPayload(error) {
  return {
    error: {
      code: mapErrorCode(error?.code),
      message: error?.message || 'Internal server error.',
      ...(error?.details ? { details: error.details } : {}),
    },
  };
}

function defaultResolveSubject(req) {
  return String(
    req?.user?.id
    || req?.user?.userId
    || req?.auth?.userId
    || ''
  ).trim() || null;
}

function defaultResolveDomain(req) {
  const origin = String(req?.headers?.origin || '').trim();
  if (origin) {
    try {
      return new URL(origin).host;
    } catch (_error) {
      return origin;
    }
  }

  return String(req?.headers?.host || '').trim() || 'walletwitness.local';
}

function defaultResolveUri(req) {
  const origin = String(req?.headers?.origin || '').trim();
  if (origin) return origin;

  const host = String(req?.headers?.host || '').trim();
  if (!host) return 'http://localhost';

  const protocol = String(req?.headers?.['x-forwarded-proto'] || req?.protocol || 'http').trim() || 'http';
  return `${protocol}://${host}`;
}

function resolveSessionHeaderValue(req, sessionHeader) {
  const value = req?.headers?.[sessionHeader];
  if (Array.isArray(value)) {
    return String(value[0] || '').trim();
  }
  return String(value || '').trim();
}

function buildStorageKey(sessionId, subject) {
  return `${String(subject || '').trim()}::${String(sessionId || '').trim()}`;
}

function sameTrust(left, right) {
  return JSON.stringify(cloneTrustSession(left)) === JSON.stringify(cloneTrustSession(right));
}

function sendPolicyError(res, {
  currentTrust,
  reason,
  requiredTrust,
}) {
  res.status(403).json({
    error: reason,
    requiredTrust,
    trust: currentTrust,
  });
}

function createWalletWitnessMiddleware(options = {}) {
  const challengeStore = options.challengeStore || createMemoryChallengeStore();
  const trustSessionStore = options.trustSessionStore || createMemoryTrustSessionStore();
  const sessionHeader = String(options.sessionHeader || DEFAULT_SESSION_HEADER).trim().toLowerCase() || DEFAULT_SESSION_HEADER;
  const expectedChainId = options.expectedChainId ?? DEFAULT_CHAIN_ID;
  const challengeTtlMs = options.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const trustSessionTtlMs = options.trustSessionTtlMs ?? DEFAULT_TRUST_SESSION_TTL_MS;
  const verifiedActionTtlMs = options.verifiedActionTtlMs ?? DEFAULT_VERIFIED_ACTION_TTL_MS;
  const appName = String(options.appName || 'WalletWitness').trim() || 'WalletWitness';
  const resolveSubject = typeof options.resolveSubject === 'function'
    ? options.resolveSubject
    : defaultResolveSubject;
  const resolveContext = typeof options.resolveContext === 'function'
    ? options.resolveContext
    : (() => undefined);
  const resolveDomain = typeof options.resolveDomain === 'function'
    ? options.resolveDomain
    : defaultResolveDomain;
  const resolveUri = typeof options.resolveUri === 'function'
    ? options.resolveUri
    : defaultResolveUri;
  const getSessionId = typeof options.getSessionId === 'function'
    ? options.getSessionId
    : (req) => resolveSessionHeaderValue(req, sessionHeader);
  const setSessionId = typeof options.setSessionId === 'function'
    ? options.setSessionId
    : (res, sessionId) => res.setHeader(sessionHeader, sessionId);

  async function attachTrustSession(req, res, next) {
    try {
      const subject = String(resolveSubject(req) || '').trim();

      if (!subject) {
        req.walletWitness = {
          sessionId: null,
          subject: null,
          trust: createAnonymousTrustSession(),
        };
        return next();
      }

      let sessionId = String(getSessionId(req, sessionHeader) || '').trim();
      if (!sessionId) {
        sessionId = `wwsess_${randomUUID()}`;
      }

      setSessionId(res, sessionId, sessionHeader);

      const storageKey = buildStorageKey(sessionId, subject);
      const storedTrust = await trustSessionStore.get(storageKey);
      const evaluatedTrust = storedTrust
        ? evaluateTrustSession(storedTrust)
        : createAuthenticatedTrustSession();

      if (storedTrust && !sameTrust(storedTrust, evaluatedTrust)) {
        await trustSessionStore.set(storageKey, evaluatedTrust);
      }

      req.walletWitness = {
        sessionId,
        subject,
        trust: evaluatedTrust,
      };

      return next();
    } catch (error) {
      return next(error);
    }
  }

  function ensureAuthenticated(req, res) {
    if (req?.walletWitness?.sessionId && req?.walletWitness?.subject) {
      return true;
    }

    res.status(401).json({
      error: 'Authenticated host session required before wallet verification.',
      requiredTrust: 'authenticated_unverified',
      trust: createAnonymousTrustSession(),
    });
    return false;
  }

  async function challengeRoute(req, res) {
    if (!ensureAuthenticated(req, res)) return;

    try {
      const currentTrust = evaluateTrustSession(req.walletWitness?.trust);
      const body = req.body || {};
      const purpose = normalizeChallengePurpose(body.purpose);
      let address = body.address;
      let chainId = body.chainId;
      let action = body.action || null;

      if (purpose === VERIFY_ACTION_PURPOSE) {
        if (currentTrust.state !== 'verified_identity' && currentTrust.state !== 'verified_action') {
          return sendPolicyError(res, {
            currentTrust,
            reason: 'Verified identity is required before requesting a scoped step-up.',
            requiredTrust: 'verified_identity',
          });
        }

        address = address || currentTrust.address;
        chainId = chainId ?? currentTrust.chainId;

        if (normalizeAddress(address) !== currentTrust.address) {
          throw makeError(
            'IDENTITY_MISMATCH',
            'Verified action step-up must use the same wallet as the current verified identity.'
          );
        }

        if (normalizeChainId(chainId) !== currentTrust.chainId) {
          throw makeError(
            'CHAIN_MISMATCH',
            `Expected chain ${currentTrust.chainId}, received chain ${normalizeChainId(chainId)}.`,
            { expectedChainId: currentTrust.chainId, actualChainId: normalizeChainId(chainId) }
          );
        }
      }

      const challenge = await issueChallenge({
        action,
        address,
        appName,
        challengeTtlMs,
        chainId,
        context: body.context ?? resolveContext(req),
        domain: resolveDomain(req),
        expectedChainId,
        purpose,
        sessionId: req.walletWitness.sessionId,
        store: challengeStore,
        subject: req.walletWitness.subject,
        uri: resolveUri(req),
        verificationTtlMs: purpose === VERIFY_ACTION_PURPOSE
          ? verifiedActionTtlMs
          : trustSessionTtlMs,
      });

      res.json({
        challenge,
        sessionId: req.walletWitness.sessionId,
        trust: currentTrust,
      });
    } catch (error) {
      res.status(mapErrorStatus(error)).json(buildErrorPayload(error));
    }
  }

  async function verifyRoute(req, res) {
    if (!ensureAuthenticated(req, res)) return;

    try {
      const storageKey = buildStorageKey(req.walletWitness.sessionId, req.walletWitness.subject);
      const currentTrust = evaluateTrustSession(
        await trustSessionStore.get(storageKey) || req.walletWitness.trust
      );
      const body = req.body || {};
      const { challenge, verificationRecord } = await verifyChallengeResponse({
        challengeId: body.challengeId,
        expectedChainId,
        message: body.message,
        signature: body.signature,
        store: challengeStore,
      });

      let trust;
      if (challenge.purpose === VERIFY_ACTION_PURPOSE) {
        if (currentTrust.state !== 'verified_identity' && currentTrust.state !== 'verified_action') {
          return sendPolicyError(res, {
            currentTrust,
            reason: 'Verified identity is required before a scoped step-up can be completed.',
            requiredTrust: 'verified_identity',
          });
        }

        if (
          currentTrust.address !== verificationRecord.address
          || currentTrust.chainId !== verificationRecord.chainId
        ) {
          throw makeError(
            'IDENTITY_MISMATCH',
            'Verified action step-up must be completed by the wallet bound to the active verified identity.'
          );
        }

        const actionGrant = issueVerifiedActionGrant({
          address: verificationRecord.address,
          scope: challenge.action?.scope,
          ttlMs: challenge.verificationTtlMs,
          now: verificationRecord.verifiedAt,
        });

        trust = attachActionGrant(currentTrust, actionGrant, {
          now: verificationRecord.verifiedAt,
        });
      } else {
        trust = createTrustSession({
          verificationRecord,
          ttlMs: trustSessionTtlMs,
        });
      }

      await trustSessionStore.set(storageKey, trust);
      req.walletWitness.trust = trust;
      setSessionId(res, req.walletWitness.sessionId, sessionHeader);

      res.json({
        sessionId: req.walletWitness.sessionId,
        trust,
      });
    } catch (error) {
      res.status(mapErrorStatus(error)).json(buildErrorPayload(error));
    }
  }

  return {
    attachTrustSession,
    challengeRoute,
    verifyRoute,
    challengeStore,
    sessionHeader,
    trustSessionStore,
  };
}

module.exports = {
  DEFAULT_SESSION_HEADER,
  createMemoryTrustSessionStore,
  createWalletWitnessMiddleware,
};
