const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');

const express = require('express');
const { privateKeyToAccount } = require('viem/accounts');

function loadClient() {
  try {
    return require('@walletwitness/client');
  } catch (_error) {
    return require('..');
  }
}

function loadServer() {
  try {
    return require('@walletwitness/server');
  } catch (_error) {
    return require('../../server');
  }
}

const {
  createTrustStateStore,
  createWalletWitnessClient,
  describeTrustState,
  renderTrustStatusBadge,
} = loadClient();
const { createWalletWitnessMiddleware } = loadServer();

const account = privateKeyToAccount(
  '0x59c6995e998f97a5a0044976f1d81f4edc7d4b6ed7f42fb178cdb5f7f8b3d1cf'
);

function normalizeHeaders(headers = {}) {
  if (!headers) return {};

  if (typeof headers.entries === 'function') {
    return Object.fromEntries(Array.from(headers.entries()));
  }

  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [String(key).toLowerCase(), value])
  );
}

function preservePrototypeMethods(instance) {
  const seen = new Set();
  let cursor = Object.getPrototypeOf(instance);

  while (cursor && cursor !== Object.prototype) {
    for (const name of Object.getOwnPropertyNames(cursor)) {
      if (name === 'constructor' || seen.has(name) || Object.prototype.hasOwnProperty.call(instance, name)) {
        continue;
      }

      const descriptor = Object.getOwnPropertyDescriptor(cursor, name);
      if (descriptor && typeof descriptor.value === 'function') {
        instance[name] = instance[name].bind(instance);
        seen.add(name);
      }
    }

    cursor = Object.getPrototypeOf(cursor);
  }
}

async function invokeApp(app, {
  body,
  headers = {},
  method = 'GET',
  path = '/',
} = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const request = new PassThrough();
    preservePrototypeMethods(request);
    request.method = String(method || 'GET').toUpperCase();
    request.url = path;
    request.originalUrl = path;
    request.headers = normalizeHeaders(headers);
    request.connection = { remoteAddress: '127.0.0.1' };
    request.socket = request.connection;
    request.httpVersion = '1.1';
    request.httpVersionMajor = 1;
    request.httpVersionMinor = 1;
    request.protocol = 'http';
    request.get = (name) => request.headers[String(name || '').toLowerCase()];

    const response = new PassThrough();
    preservePrototypeMethods(response);
    const chunks = [];
    const responseHeaders = new Map();

    response.locals = {};
    response.statusCode = 200;
    response.headersSent = false;
    response.setHeader = (name, value) => {
      responseHeaders.set(String(name || '').toLowerCase(), value);
    };
    response.getHeader = (name) => responseHeaders.get(String(name || '').toLowerCase());
    response.getHeaders = () => Object.fromEntries(responseHeaders.entries());
    response.removeHeader = (name) => responseHeaders.delete(String(name || '').toLowerCase());
    response.writeHead = (statusCode, headerValues = {}) => {
      response.statusCode = statusCode;
      for (const [name, value] of Object.entries(headerValues || {})) {
        response.setHeader(name, value);
      }
      return response;
    };
    response.write = (chunk, encoding, callback) => {
      if (chunk) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
      }
      if (typeof callback === 'function') callback();
      return true;
    };
    response.end = (chunk, encoding, callback) => {
      if (settled) return response;

      if (chunk) {
        response.write(chunk, encoding);
      }

      response.finished = true;
      response.headersSent = true;
      settled = true;
      if (typeof callback === 'function') callback();

      resolve({
        status: response.statusCode,
        headers: Object.fromEntries(responseHeaders.entries()),
        body: Buffer.concat(chunks).toString('utf8'),
      });
      return response;
    };

    const serializedBody = body === undefined || body === null
      ? null
      : Buffer.from(
          typeof body === 'string'
            ? body
            : JSON.stringify(body)
        );

    if (serializedBody && !request.headers['content-type']) {
      request.headers['content-type'] = 'application/json';
    }
    if (serializedBody) {
      request.headers['content-length'] = String(serializedBody.length);
    }

    app.handle(request, response, (error) => {
      if (settled) return;
      if (error) {
        settled = true;
        reject(error);
        return;
      }

      response.end();
    });

    if (serializedBody) {
      request.push(serializedBody);
    }
    request.push(null);
  });
}

function createFetchAdapter(app) {
  return async function fetchAdapter(url, init = {}) {
    const target = new URL(String(url || '/'), 'http://walletwitness.local');
    const result = await invokeApp(app, {
      body: init.body,
      headers: init.headers || {},
      method: init.method || 'GET',
      path: `${target.pathname}${target.search}`,
    });

    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status,
      headers: {
        get(name) {
          return result.headers[String(name || '').toLowerCase()] || null;
        },
      },
      async json() {
        return JSON.parse(result.body || 'null');
      },
      async text() {
        return result.body;
      },
    };
  };
}

function createRuntime() {
  const app = express();
  app.use(express.json());

  const walletWitness = createWalletWitnessMiddleware({
    appName: 'WalletWitness Demo',
    expectedChainId: 8453,
    resolveSubject(req) {
      return String(req.headers['x-demo-user'] || '').trim() || null;
    },
  });

  app.use(walletWitness.attachTrustSession);
  app.get('/session', (req, res) => {
    res.json({
      sessionId: req.walletWitness.sessionId,
      trust: req.walletWitness.trust,
    });
  });
  app.post('/wallet/challenge', walletWitness.challengeRoute);
  app.post('/wallet/verify', walletWitness.verifyRoute);

  return {
    fetch: createFetchAdapter(app),
  };
}

test('client helpers complete verify-session and step-up flows', async () => {
  const runtime = createRuntime();
  const trustStore = createTrustStateStore();
  const client = createWalletWitnessClient({
    baseUrl: 'http://walletwitness.local',
    defaultHeaders: {
      'x-demo-user': 'user-jun',
    },
    fetch: runtime.fetch,
    trustStore,
  });

  const sessionFlow = await client.verifySession({
    address: account.address,
    chainId: 8453,
    signer: account,
  });

  assert.ok(client.getSessionId());
  assert.equal(sessionFlow.verifyResponse.trust.state, 'verified_identity');
  assert.equal(trustStore.get().state, 'verified_identity');

  const stepUpFlow = await client.verifyAction({
    action: {
      kind: 'delete',
      scope: 'demo:dangerous-delete',
    },
    signer: account,
  });

  assert.equal(stepUpFlow.verifyResponse.trust.state, 'verified_action');
  assert.equal(trustStore.get().actionGrant.scope, 'demo:dangerous-delete');

  const sessionPayload = await client.getSession();
  assert.equal(sessionPayload.trust.state, 'verified_action');

  const summary = describeTrustState(trustStore.get());
  assert.equal(summary.state, 'verified_action');
  assert.match(summary.detail, /demo:dangerous-delete/);
  assert.match(
    renderTrustStatusBadge(trustStore.get()),
    /data-walletwitness-trust="verified_action"/
  );
});

test('trust store normalizes snapshots and escapes widget output', () => {
  const store = createTrustStateStore();
  const seenStates = [];
  const unsubscribe = store.subscribe((trust) => {
    seenStates.push(trust.state);
  });

  store.set({
    state: 'verified_action',
    actionGrant: {
      scope: 'demo:<dangerous-delete>',
      expiresAt: 2_000,
    },
    expiresAt: 2_000,
  });
  unsubscribe();
  store.set(null);

  assert.deepEqual(seenStates, ['verified_action']);
  assert.equal(store.get().state, 'anonymous');
  assert.match(
    renderTrustStatusBadge({
      state: 'verified_action',
      actionGrant: {
        scope: 'demo:<dangerous-delete>',
        expiresAt: 2_000,
      },
      expiresAt: 2_000,
    }),
    /demo:&lt;dangerous-delete&gt;/
  );
});
