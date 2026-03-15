const DEFAULT_CHALLENGE_PATH = '/wallet/challenge';
const DEFAULT_SESSION_HEADER = 'x-walletwitness-session';
const DEFAULT_SESSION_PATH = '/session';
const DEFAULT_VERIFY_PATH = '/wallet/verify';

function normalizeOptionalString(value) {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function normalizeHeaders(headers = {}) {
  if (!headers) return {};

  if (typeof headers.entries === 'function') {
    return Object.fromEntries(Array.from(headers.entries()));
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }

  return { ...headers };
}

function getHeaderValue(headers, name) {
  if (!headers) return null;

  if (typeof headers.get === 'function') {
    return headers.get(name);
  }

  const normalizedName = String(name || '').toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (String(key || '').toLowerCase() === normalizedName) {
      return value;
    }
  }

  return null;
}

function joinUrl(baseUrl, path) {
  const target = String(path || '').trim() || '/';
  if (/^https?:\/\//i.test(target)) {
    return target;
  }

  const normalizedBaseUrl = normalizeOptionalString(baseUrl);
  if (!normalizedBaseUrl) {
    return target;
  }

  return new URL(target, normalizedBaseUrl).toString();
}

async function parseResponsePayload(response) {
  if (typeof response?.json === 'function') {
    try {
      return await response.json();
    } catch (_error) {
      if (typeof response.text !== 'function') {
        return null;
      }
    }
  }

  if (typeof response?.text !== 'function') {
    return null;
  }

  const text = await response.text();
  if (!text) return null;

  try {
    return JSON.parse(text);
  } catch (_error) {
    return { raw: text };
  }
}

function createHttpError({ payload, response }) {
  const code = normalizeOptionalString(payload?.error?.code);
  const error = new Error(
    payload?.error?.message
    || `WalletWitness request failed with status ${response?.status || 'unknown'}.`
  );

  error.code = code ? code.toUpperCase() : 'HTTP_ERROR';
  error.payload = payload || null;
  error.status = Number(response?.status) || 500;
  return error;
}

async function signChallengeMessage({
  challenge,
  signer,
}) {
  const message = normalizeOptionalString(challenge?.message);
  if (!message) {
    throw new Error('Challenge message is required before it can be signed.');
  }

  if (typeof signer === 'function') {
    return String(await signer({ message }) || '').trim();
  }

  if (signer && typeof signer.signMessage === 'function') {
    return String(await signer.signMessage({ message }) || '').trim();
  }

  throw new Error('A signer function or signer object with signMessage({ message }) is required.');
}

function createWalletWitnessClient(options = {}) {
  const fetchImpl = options.fetch || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('createWalletWitnessClient requires a fetch implementation.');
  }

  const baseUrl = normalizeOptionalString(options.baseUrl);
  const challengePath = normalizeOptionalString(options.challengePath) || DEFAULT_CHALLENGE_PATH;
  const sessionHeader = String(options.sessionHeader || DEFAULT_SESSION_HEADER).trim().toLowerCase() || DEFAULT_SESSION_HEADER;
  const sessionPath = normalizeOptionalString(options.sessionPath) || DEFAULT_SESSION_PATH;
  const verifyPath = normalizeOptionalString(options.verifyPath) || DEFAULT_VERIFY_PATH;
  const trustStore = options.trustStore && typeof options.trustStore.set === 'function'
    ? options.trustStore
    : null;
  const defaultHeaders = normalizeHeaders(options.defaultHeaders);

  let sessionId = normalizeOptionalString(options.sessionId);

  function updateSessionId(response) {
    const nextSessionId = normalizeOptionalString(getHeaderValue(response?.headers, sessionHeader));
    if (!nextSessionId) return sessionId;

    sessionId = nextSessionId;
    if (typeof options.onSessionId === 'function') {
      options.onSessionId(sessionId);
    }

    return sessionId;
  }

  function updateTrust(payload) {
    if (!payload || typeof payload !== 'object' || !payload.trust) {
      return;
    }

    if (trustStore) {
      trustStore.set(payload.trust);
    }

    if (typeof options.onTrustChange === 'function') {
      options.onTrustChange(payload.trust);
    }
  }

  async function requestJson(path, {
    body,
    headers,
    method = 'POST',
  } = {}) {
    const requestHeaders = {
      accept: 'application/json',
      ...defaultHeaders,
      ...normalizeHeaders(headers),
    };

    if (body !== undefined && !getHeaderValue(requestHeaders, 'content-type')) {
      requestHeaders['content-type'] = 'application/json';
    }

    if (sessionId && !getHeaderValue(requestHeaders, sessionHeader)) {
      requestHeaders[sessionHeader] = sessionId;
    }

    const response = await fetchImpl(joinUrl(baseUrl, path), {
      method,
      headers: requestHeaders,
      ...(body !== undefined
        ? {
            body: typeof body === 'string' ? body : JSON.stringify(body),
          }
        : {}),
    });

    const payload = await parseResponsePayload(response);
    updateSessionId(response);
    updateTrust(payload);

    if (!response.ok) {
      throw createHttpError({ payload, response });
    }

    return payload;
  }

  async function getSession(requestOptions = {}) {
    return requestJson(sessionPath, {
      method: 'GET',
      headers: requestOptions.headers,
    });
  }

  async function requestChallenge(body, requestOptions = {}) {
    return requestJson(challengePath, {
      method: 'POST',
      body,
      headers: requestOptions.headers,
    });
  }

  async function verifyChallenge(body, requestOptions = {}) {
    return requestJson(verifyPath, {
      method: 'POST',
      body,
      headers: requestOptions.headers,
    });
  }

  async function verifySession({
    address,
    chainId,
    signer,
    ...body
  } = {}, requestOptions = {}) {
    const challengeResponse = await requestChallenge({
      ...body,
      address,
      chainId,
      purpose: 'verify-session',
    }, requestOptions);
    const signature = await signChallengeMessage({
      challenge: challengeResponse?.challenge,
      signer,
    });
    const verifyResponse = await verifyChallenge({
      challengeId: challengeResponse.challenge.challengeId,
      message: challengeResponse.challenge.message,
      signature,
    }, requestOptions);

    return {
      challenge: challengeResponse.challenge,
      challengeResponse,
      signature,
      verifyResponse,
    };
  }

  async function verifyAction({
    action,
    signer,
    ...body
  } = {}, requestOptions = {}) {
    const challengeResponse = await requestChallenge({
      ...body,
      purpose: 'verify-action',
      action,
    }, requestOptions);
    const signature = await signChallengeMessage({
      challenge: challengeResponse?.challenge,
      signer,
    });
    const verifyResponse = await verifyChallenge({
      challengeId: challengeResponse.challenge.challengeId,
      message: challengeResponse.challenge.message,
      signature,
    }, requestOptions);

    return {
      challenge: challengeResponse.challenge,
      challengeResponse,
      signature,
      verifyResponse,
    };
  }

  return {
    clearSessionId() {
      sessionId = undefined;
    },
    getSession,
    getSessionId() {
      return sessionId;
    },
    requestChallenge,
    requestJson,
    setSessionId(value) {
      sessionId = normalizeOptionalString(value);
      return sessionId;
    },
    verifyAction,
    verifyChallenge,
    verifySession,
  };
}

module.exports = {
  DEFAULT_CHALLENGE_PATH,
  DEFAULT_SESSION_HEADER,
  DEFAULT_SESSION_PATH,
  DEFAULT_VERIFY_PATH,
  createWalletWitnessClient,
  signChallengeMessage,
};
