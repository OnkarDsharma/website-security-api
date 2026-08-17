const assert = require('node:assert/strict');
const test = require('node:test');

const { checkCMSVersion } = require('../lib/checkCMS');
const { findingShapeAssert, makeResponse } = require('./helpers');

test('checkCMSVersion flags old WordPress versions', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({
    body: '<meta name="generator" content="WordPress 5.9.9">'
  }));

  const findings = await checkCMSVersion('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'wordpress_version');
  assert.equal(findings[0].status, 'fail');
  assert.equal(findings[0].severity, 'medium');
  findingShapeAssert(findings[0]);
});

test('checkCMSVersion reports current CMS versions as informational', async (t) => {
  t.mock.method(global, 'fetch', async () => makeResponse({
    body: '<meta name="generator" content="Joomla! 4.4.0">'
  }));

  const findings = await checkCMSVersion('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'joomla_version');
  assert.equal(findings[0].status, 'info');
  assert.equal(findings[0].severity, 'low');
});

test('checkCMSVersion reports unreachable targets', async (t) => {
  t.mock.method(global, 'fetch', async () => {
    throw new Error('timeout');
  });

  const findings = await checkCMSVersion('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'cms');
  assert.equal(findings[0].check, 'reachability');
  assert.equal(findings[0].status, 'unreachable');
  assert.equal(findings[0].severity, 'info');
});
