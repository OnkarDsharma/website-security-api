const assert = require('node:assert/strict');
const dns = require('node:dns').promises;
const test = require('node:test');

const { isSafeUrl } = require('../lib/urlSafety');

test('isSafeUrl blocks localhost', async () => {
  assert.deepEqual(await isSafeUrl('https://localhost'), {
    safe: false,
    reason: 'Scanning localhost is not allowed.'
  });
});

test('isSafeUrl blocks private IP literals', async () => {
  assert.deepEqual(await isSafeUrl('https://192.168.1.10'), {
    safe: false,
    reason: 'Scanning private/internal IP addresses is not allowed.'
  });
});

test('isSafeUrl blocks domains resolving to private addresses', async (t) => {
  t.mock.method(dns, 'lookup', async () => [{ address: '10.0.0.5', family: 4 }]);

  assert.deepEqual(await isSafeUrl('https://internal.example'), {
    safe: false,
    reason: 'This domain resolves to a private/internal IP address, which is not allowed.'
  });
});

test('isSafeUrl allows public addresses', async (t) => {
  t.mock.method(dns, 'lookup', async () => [{ address: '93.184.216.34', family: 4 }]);

  assert.deepEqual(await isSafeUrl('https://example.com'), { safe: true });
});
