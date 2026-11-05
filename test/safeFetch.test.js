const assert = require('node:assert/strict');
const dns = require('node:dns');
const test = require('node:test');

const { client, safeFetch, MAX_REDIRECTS } = require('../lib/safeFetch');
const { isSafeUrl, safeLookup } = require('../lib/urlSafety');
const { checkSecurityHeaders } = require('../lib/checkHeaders');
const { makeResponse } = require('./helpers');

// A public IP literal, so these tests never depend on real DNS.
const PUBLIC_URL = 'https://93.184.216.34/';

test('isSafeUrl blocks encoded and less-common internal addresses', async () => {
  const blocked = [
    'http://[::1]/',
    'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:169.254.169.254]/',
    'http://[fd00::1]/',
    'http://169.254.169.254/latest/meta-data/',
    'http://100.64.0.1/',
    'http://0.0.0.0/',
    'http://2130706433/',   // decimal 127.0.0.1
    'http://0x7f.1/',       // hex shorthand for 127.0.0.1
    'http://localhost./',
    'http://user:pass@example.com/'
  ];

  for (const url of blocked) {
    const result = await isSafeUrl(url);
    assert.equal(result.safe, false, `${url} should be blocked`);
  }
});

test('isSafeUrl rejects non-http protocols', async () => {
  assert.equal((await isSafeUrl('file:///etc/passwd')).safe, false);
  assert.equal((await isSafeUrl('gopher://example.com/')).safe, false);
});

test('safeFetch refuses to follow a redirect to cloud metadata', async (t) => {
  const requested = [];
  t.mock.method(client, 'fetch', async (url) => {
    requested.push(url);
    return makeResponse({
      status: 302,
      headers: { location: 'http://169.254.169.254/latest/meta-data/' }
    });
  });

  await assert.rejects(safeFetch(PUBLIC_URL), { code: 'EBLOCKEDTARGET' });
  assert.deepEqual(requested, [PUBLIC_URL]);
});

test('safeFetch refuses redirects to IPv6 loopback', async (t) => {
  t.mock.method(client, 'fetch', async () => makeResponse({
    status: 301,
    headers: { location: 'http://[::1]:8080/admin' }
  }));

  await assert.rejects(safeFetch(PUBLIC_URL), { code: 'EBLOCKEDTARGET' });
  assert.equal(client.fetch.mock.callCount(), 1);
});

test('safeFetch follows safe redirects and never lets fetch follow on its own', async (t) => {
  t.mock.method(client, 'fetch', async (url, options) => {
    assert.equal(options.redirect, 'manual');
    if (url === PUBLIC_URL) {
      return makeResponse({ status: 301, headers: { location: '/landing' } });
    }
    return makeResponse({ status: 200, body: 'ok' });
  });

  const response = await safeFetch(PUBLIC_URL);
  assert.equal(response.status, 200);
  assert.deepEqual(
    client.fetch.mock.calls.map((call) => call.arguments[0]),
    [PUBLIC_URL, 'https://93.184.216.34/landing']
  );
});

test('safeFetch stops after too many redirects', async (t) => {
  t.mock.method(client, 'fetch', async () => makeResponse({
    status: 302,
    headers: { location: PUBLIC_URL }
  }));

  await assert.rejects(safeFetch(PUBLIC_URL), /Too many redirects/);
  assert.equal(client.fetch.mock.callCount(), MAX_REDIRECTS + 1);
});

test('safeFetch with redirect: manual returns the redirect untouched', async (t) => {
  t.mock.method(client, 'fetch', async () => makeResponse({
    status: 302,
    headers: { location: 'http://127.0.0.1/' }
  }));

  const response = await safeFetch(PUBLIC_URL, { redirect: 'manual' });
  assert.equal(response.status, 302);
  assert.equal(client.fetch.mock.callCount(), 1);
});

test('safeFetch blocks a direct request to a private address', async (t) => {
  t.mock.method(client, 'fetch', async () => makeResponse());

  await assert.rejects(safeFetch('http://127.0.0.1:3000/'), { code: 'EBLOCKEDTARGET' });
  assert.equal(client.fetch.mock.callCount(), 0);
});

test('safeLookup rejects DNS answers that point at private addresses (rebinding)', async (t) => {
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    callback(null, [
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.5', family: 4 }
    ]);
  });

  await new Promise((resolve) => {
    safeLookup('rebind.example', { all: true }, (err) => {
      assert.equal(err.code, 'EBLOCKEDADDRESS');
      resolve();
    });
  });
});

test('safeLookup passes through public answers in both callback shapes', async (t) => {
  t.mock.method(dns, 'lookup', (hostname, options, callback) => {
    callback(null, [{ address: '93.184.216.34', family: 4 }]);
  });

  await new Promise((resolve) => {
    safeLookup('example.com', { all: true }, (err, addresses) => {
      assert.equal(err, null);
      assert.deepEqual(addresses, [{ address: '93.184.216.34', family: 4 }]);
      resolve();
    });
  });

  await new Promise((resolve) => {
    safeLookup('example.com', { family: 4 }, (err, address, family) => {
      assert.equal(err, null);
      assert.equal(address, '93.184.216.34');
      assert.equal(family, 4);
      resolve();
    });
  });
});

test('a checker reports a blocked redirect instead of fetching it', async (t) => {
  t.mock.method(client, 'fetch', async () => makeResponse({
    status: 302,
    headers: { location: 'http://169.254.169.254/' }
  }));

  const findings = await checkSecurityHeaders(PUBLIC_URL);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].status, 'unreachable');
  assert.match(findings[0].detail, /Blocked unsafe target/);
  assert.equal(client.fetch.mock.callCount(), 1);
});
