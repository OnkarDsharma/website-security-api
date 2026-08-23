const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const { createMockResponse } = require('./helpers');

const root = path.resolve(__dirname, '..');

function setMockModule(relativePath, exports) {
  const filename = path.join(root, relativePath);
  require.cache[filename] = {
    id: filename,
    filename,
    loaded: true,
    exports
  };
}

function loadHandler(relativePath, mocks) {
  const handlerPath = path.join(root, relativePath);
  delete require.cache[handlerPath];

  for (const [mockPath, exports] of Object.entries(mocks)) {
    setMockModule(mockPath, exports);
  }

  return require(handlerPath);
}

test('full scan rejects missing and invalid urls', async () => {
  const handler = require('../api/scan');

  const missingRes = createMockResponse();
  await handler({ query: {} }, missingRes);
  assert.equal(missingRes.statusCode, 400);
  assert.equal(missingRes.body.error, 'Missing required query parameter: url');

  const invalidRes = createMockResponse();
  await handler({ query: { url: 'notaurl' } }, invalidRes);
  assert.equal(invalidRes.statusCode, 400);
  assert.equal(invalidRes.body.error, 'Invalid url. Must start with http:// or https://');
});

test('full scan rejects unsafe urls before running checks', async () => {
  let checkCalled = false;
  const handler = loadHandler('api/scan.js', {
    'lib/urlSafety.js': {
      isSafeUrl: async () => ({ safe: false, reason: 'blocked' })
    },
    'lib/checkHeaders.js': {
      checkSecurityHeaders: async () => {
        checkCalled = true;
        return [];
      }
    },
    'lib/checkSSL.js': { checkSSL: async () => [] },
    'lib/checkExposedPaths.js': { checkExposedPaths: async () => [] },
    'lib/checkCMS.js': { checkCMSVersion: async () => [] },
    'lib/checkServerLeakage.js': { checkServerLeakage: async () => [] },
    'lib/scoring.js': {
      calculateRisk: () => ({ score: 100, riskLevel: 'low', summary: {} })
    }
  });

  const res = createMockResponse();
  await handler({ query: { url: 'https://example.com' } }, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'blocked');
  assert.equal(checkCalled, false);
});

test('full scan merges checker findings and scores response', async () => {
  const handler = loadHandler('api/scan.js', {
    'lib/urlSafety.js': { isSafeUrl: async () => ({ safe: true }) },
    'lib/checkHeaders.js': {
      checkSecurityHeaders: async () => [{ category: 'headers', check: 'HSTS', status: 'missing', severity: 'high', detail: 'missing' }]
    },
    'lib/checkSSL.js': { checkSSL: async () => [] },
    'lib/checkExposedPaths.js': {
      checkExposedPaths: async () => [{ category: 'exposed_paths', check: '/.env', status: 'fail', severity: 'critical', detail: 'exposed' }]
    },
    'lib/checkCMS.js': { checkCMSVersion: async () => [] },
    'lib/checkServerLeakage.js': { checkServerLeakage: async () => [] },
    'lib/scoring.js': {
      calculateRisk: (findings) => ({
        score: 60,
        riskLevel: 'moderate',
        summary: { count: findings.length }
      })
    }
  });

  const res = createMockResponse();
  await handler({ query: { url: 'https://example.com' } }, res);

  assert.equal(res.statusCode, 200);
  assert.equal(res.body.url, 'https://example.com');
  assert.equal(res.body.security_score, 60);
  assert.equal(res.body.risk_level, 'moderate');
  assert.equal(res.body.findings.length, 2);
  assert.equal(res.body.summary.count, 2);
  assert.match(res.body.scanned_at, /^\d{4}-\d{2}-\d{2}T/);
});

test('quick scan rejects unsafe urls before running checks', async () => {
  let checkCalled = false;
  const handler = loadHandler('api/scan/quick.js', {
    'lib/urlSafety.js': {
      isSafeUrl: async () => ({ safe: false, reason: 'blocked' })
    },
    'lib/checkHeaders.js': {
      checkSecurityHeaders: async () => {
        checkCalled = true;
        return [];
      }
    },
    'lib/checkSSL.js': { checkSSL: async () => [] },
    'lib/scoring.js': {
      calculateRisk: () => ({ score: 100, riskLevel: 'low', summary: {} })
    }
  });

  const res = createMockResponse();
  await handler({ query: { url: 'https://example.com' } }, res);

  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'blocked');
  assert.equal(checkCalled, false);
});

test('public scan rejects requests outside the landing page origins', async () => {
  const handler = require('../api/public-scan');

  const missingOriginRes = createMockResponse();
  await handler({ headers: {}, query: { url: 'https://example.com' } }, missingOriginRes);
  assert.equal(missingOriginRes.statusCode, 403);
  assert.equal(missingOriginRes.body.error, 'This endpoint is only available from the official landing page.');

  const spoofedOriginRes = createMockResponse();
  await handler({
    headers: { origin: 'https://website-security-scanner-api.vercel.app.evil.test' },
    query: { url: 'https://example.com' }
  }, spoofedOriginRes);
  assert.equal(spoofedOriginRes.statusCode, 403);
});

test('public scan accepts allowed landing page origins and scores response', async () => {
  const handler = loadHandler('api/public-scan.js', {
    'lib/urlSafety.js': { isSafeUrl: async () => ({ safe: true }) },
    'lib/checkHeaders.js': {
      checkSecurityHeaders: async () => [{ category: 'headers', check: 'HSTS', status: 'missing', severity: 'high', detail: 'missing' }]
    },
    'lib/checkSSL.js': { checkSSL: async () => [] },
    'lib/checkExposedPaths.js': { checkExposedPaths: async () => [] },
    'lib/checkCMS.js': { checkCMSVersion: async () => [] },
    'lib/checkServerLeakage.js': { checkServerLeakage: async () => [] },
    'lib/scoring.js': {
      calculateRisk: (findings) => ({
        score: 85,
        riskLevel: 'low',
        summary: { count: findings.length }
      })
    }
  });

  for (const referer of ['http://localhost:3000/', 'http://localhost:3001/']) {
    const res = createMockResponse();
    await handler({
      headers: { referer },
      query: { url: 'https://example.com' }
    }, res);

    assert.equal(res.statusCode, 200);
    assert.equal(res.body.url, 'https://example.com');
    assert.equal(res.body.security_score, 85);
    assert.equal(res.body.risk_level, 'low');
    assert.equal(res.body.findings.length, 1);
    assert.equal(res.body.summary.count, 1);
  }
});
