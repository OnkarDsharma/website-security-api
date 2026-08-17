const assert = require('node:assert/strict');
const test = require('node:test');

const { checkServerLeakage } = require('../lib/checkServerLeakage');
const { findingShapeAssert, makeResponse } = require('./helpers');

test('checkServerLeakage ignores bare server names', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({
    headers: { server: 'nginx' }
  }));

  const findings = await checkServerLeakage('https://example.com');

  assert.deepEqual(findings, []);
});

test('checkServerLeakage flags versioned Server and X-Powered-By headers', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({
    headers: {
      server: 'nginx/1.18.0',
      'x-powered-by': 'Express'
    }
  }));

  const findings = await checkServerLeakage('https://example.com');

  assert.deepEqual(
    findings.map((finding) => finding.check),
    ['Server header', 'X-Powered-By header']
  );
  findings.forEach(findingShapeAssert);
});
