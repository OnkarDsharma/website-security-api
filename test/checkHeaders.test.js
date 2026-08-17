const assert = require('node:assert/strict');
const test = require('node:test');

const { checkSecurityHeaders } = require('../lib/checkHeaders');
const { findingShapeAssert, makeResponse } = require('./helpers');

test('checkSecurityHeaders returns missing security header findings', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse());

  const findings = await checkSecurityHeaders('https://example.com');

  assert.equal(findings.length, 5);
  assert.deepEqual(
    findings.map((finding) => finding.check).sort(),
    [
      'Content-Security-Policy',
      'HSTS',
      'Referrer-Policy',
      'X-Content-Type-Options',
      'X-Frame-Options'
    ]
  );
  findings.forEach(findingShapeAssert);
});

test('checkSecurityHeaders returns no findings when all headers are present', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({
    headers: {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    }
  }));

  const findings = await checkSecurityHeaders('https://example.com');

  assert.deepEqual(findings, []);
});

test('checkSecurityHeaders reports unreachable targets', async (t) => {
  t.mock.method(global, 'fetch', async () => {
    throw new Error('network down');
  });

  const findings = await checkSecurityHeaders('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'headers');
  assert.equal(findings[0].check, 'reachability');
  assert.equal(findings[0].status, 'unreachable');
  assert.equal(findings[0].severity, 'info');
  findingShapeAssert(findings[0]);
});
