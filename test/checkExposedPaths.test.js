const assert = require('node:assert/strict');
const test = require('node:test');

const { checkExposedPaths } = require('../lib/checkExposedPaths');
const { findingShapeAssert, makeResponse } = require('./helpers');

test('checkExposedPaths returns inconclusive when baseline path returns 200', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({ status: 200 }));

  const findings = await checkExposedPaths('https://example.com/page');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'baseline');
  assert.equal(findings[0].status, 'inconclusive');
  findingShapeAssert(findings[0]);
});

test('checkExposedPaths flags real file-looking leaks and skips HTML decoys', async (t) => {
  t.mock.method(global, 'fetch', async (url) => {
    const path = new URL(url).pathname;

    if (path.startsWith('/this-path-should-never-exist-')) {
      return makeResponse({ status: 404 });
    }

    if (path === '/.env') {
      return makeResponse({
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: 'DATABASE_URL=postgres://example'
      });
    }

    if (path === '/.git/config') {
      return makeResponse({
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: '<html>blocked</html>'
      });
    }

    if (path === '/admin') {
      return makeResponse({ status: 200, headers: { 'content-type': 'text/html' } });
    }

    return makeResponse({ status: 404 });
  });

  const findings = await checkExposedPaths('https://example.com/some/path');

  assert.deepEqual(
    findings.map((finding) => finding.check).sort(),
    ['/.env', '/admin']
  );
  findings.forEach(findingShapeAssert);
});

test('checkExposedPaths reports unreachable targets on baseline failure', async (t) => {
  t.mock.method(global, 'fetch', async () => {
    throw new Error('connection refused');
  });

  const findings = await checkExposedPaths('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'exposed_paths');
  assert.equal(findings[0].check, 'reachability');
  assert.equal(findings[0].status, 'unreachable');
  assert.equal(findings[0].severity, 'info');
});
