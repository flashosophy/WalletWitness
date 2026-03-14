const { PassThrough } = require('node:stream');

const express = require('express');
const { privateKeyToAccount } = require('viem/accounts');

function loadCore() {
  try {
    return require('@walletwitness/core');
  } catch (_error) {
    return require('../packages/core');
  }
}

function loadServer() {
  try {
    return require('@walletwitness/server');
  } catch (_error) {
    return require('../packages/server');
  }
}

const { trustSatisfiesRequirement } = loadCore();
const {
  createWalletWitnessMiddleware,
  createProtectMiddleware,
} = loadServer();

function normalizeHeaders(headers = {}) {
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

      const responseBody = Buffer.concat(chunks).toString('utf8');
      resolve({
        status: response.statusCode,
        headers: Object.fromEntries(responseHeaders.entries()),
        body: responseBody,
        json() {
          return JSON.parse(responseBody || 'null');
        },
      });
      return response;
    };

    const serializedBody = body === undefined
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
      request.end(serializedBody);
    } else {
      request.end();
    }
  });
}

function buildApp() {
  const app = express();
  app.use(express.json());

  const walletWitness = createWalletWitnessMiddleware({
    appName: 'WalletWitness Demo',
    expectedChainId: 8453,
    resolveSubject(req) {
      return String(req.headers['x-demo-user'] || '').trim() || null;
    },
  });

  const readPolicy = createProtectMiddleware({
    policy({ trust }) {
      return {
        allow: trustSatisfiesRequirement(trust, 'verified_identity'),
        reason: 'Verified identity required.',
        requiredTrust: 'verified_identity',
      };
    },
  });

  const deletePolicy = createProtectMiddleware({
    resolveAction() {
      return {
        kind: 'delete',
        scope: 'demo:dangerous-delete',
      };
    },
    policy({ trust, action }) {
      return {
        allow: trustSatisfiesRequirement(trust, 'verified_action', action),
        reason: 'Verified action required for dangerous delete.',
        requiredTrust: 'verified_action',
      };
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
  app.post('/notes', readPolicy, (_req, res) => {
    res.json({ ok: true, route: 'notes' });
  });
  app.post('/dangerous', deletePolicy, (_req, res) => {
    res.json({ ok: true, route: 'dangerous' });
  });

  return app;
}

function responseHeader(result, name) {
  return result.headers[String(name || '').toLowerCase()] || null;
}

function sessionHeaders(userId, sessionId) {
  return {
    'x-demo-user': userId,
    ...(sessionId ? { 'x-walletwitness-session': sessionId } : {}),
  };
}

async function main() {
  const account = privateKeyToAccount(
    '0x59c6995e998f97a5a0044976f1d81f4edc7d4b6ed7f42fb178cdb5f7f8b3d1cf'
  );
  const app = buildApp();

  const sessionChallenge = await invokeApp(app, {
    method: 'POST',
    path: '/wallet/challenge',
    headers: sessionHeaders('user-jun'),
    body: {
      address: account.address,
      chainId: 8453,
    },
  });
  const sessionChallengePayload = sessionChallenge.json();
  const sessionId = responseHeader(sessionChallenge, 'x-walletwitness-session');

  const verifySignature = await account.signMessage({
    message: sessionChallengePayload.challenge.message,
  });
  const verifySession = await invokeApp(app, {
    method: 'POST',
    path: '/wallet/verify',
    headers: sessionHeaders('user-jun', sessionId),
    body: {
      challengeId: sessionChallengePayload.challenge.challengeId,
      message: sessionChallengePayload.challenge.message,
      signature: verifySignature,
    },
  });
  const verifySessionPayload = verifySession.json();

  const blockedDangerous = await invokeApp(app, {
    method: 'POST',
    path: '/dangerous',
    headers: sessionHeaders('user-jun', sessionId),
  });
  const blockedDangerousPayload = blockedDangerous.json();

  const stepUpChallenge = await invokeApp(app, {
    method: 'POST',
    path: '/wallet/challenge',
    headers: sessionHeaders('user-jun', sessionId),
    body: {
      purpose: 'verify-action',
      action: {
        kind: 'delete',
        scope: 'demo:dangerous-delete',
      },
    },
  });
  const stepUpChallengePayload = stepUpChallenge.json();

  const stepUpSignature = await account.signMessage({
    message: stepUpChallengePayload.challenge.message,
  });
  const stepUpVerify = await invokeApp(app, {
    method: 'POST',
    path: '/wallet/verify',
    headers: sessionHeaders('user-jun', sessionId),
    body: {
      challengeId: stepUpChallengePayload.challenge.challengeId,
      message: stepUpChallengePayload.challenge.message,
      signature: stepUpSignature,
    },
  });
  const stepUpVerifyPayload = stepUpVerify.json();

  const allowedDangerous = await invokeApp(app, {
    method: 'POST',
    path: '/dangerous',
    headers: sessionHeaders('user-jun', sessionId),
  });
  const allowedDangerousPayload = allowedDangerous.json();

  console.log('WalletWitness demo');
  console.log(`Session challenge issued: ${sessionChallengePayload.challenge.challengeId}`);
  console.log(`Trust after verify-session: ${verifySessionPayload.trust.state}`);
  console.log(`Protected action before step-up: ${blockedDangerous.status} ${blockedDangerousPayload.error}`);
  console.log(`Step-up challenge issued: ${stepUpChallengePayload.challenge.challengeId}`);
  console.log(`Trust after verify-action: ${stepUpVerifyPayload.trust.state} (${stepUpVerifyPayload.trust.actionGrant.scope})`);
  console.log(`Protected action after step-up: ${allowedDangerous.status} ${JSON.stringify(allowedDangerousPayload)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
