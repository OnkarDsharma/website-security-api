const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const tls = require('node:tls');
const test = require('node:test');

const { checkSSL } = require('../lib/checkSSL');
const { findingShapeAssert } = require('./helpers');

function createFakeSocket({
  authorized = true,
  authorizationError = null,
  cert = {},
  protocol = 'TLSv1.3'
} = {}) {
  const socket = new EventEmitter();
  socket.authorized = authorized;
  socket.authorizationError = authorizationError;
  socket.getPeerCertificate = () => cert;
  socket.getProtocol = () => protocol;
  socket.end = () => {};
  socket.destroy = () => {};
  return socket;
}

test('checkSSL flags untrusted expired certificates and outdated TLS', async (t) => {
  const socket = createFakeSocket({
    authorized: false,
    authorizationError: 'SELF_SIGNED_CERT_IN_CHAIN',
    cert: { valid_to: new Date(Date.now() - 24 * 60 * 60 * 1000).toUTCString() },
    protocol: 'TLSv1'
  });

  t.mock.method(tls, 'connect', (options, onConnect) => {
    assert.equal(options.host, 'example.com');
    assert.equal(options.port, 443);
    assert.equal(options.family, 4);
    assert.equal(options.servername, 'example.com');
    assert.equal(options.rejectUnauthorized, false);
    process.nextTick(onConnect);
    return socket;
  });

  const findings = await checkSSL('https://example.com');

  assert.deepEqual(
    findings.map((finding) => finding.check).sort(),
    ['certificate_expiry', 'certificate_trust', 'tls_version']
  );
  assert.equal(findings.find((finding) => finding.check === 'certificate_expiry').severity, 'critical');
  findings.forEach(findingShapeAssert);
});

test('checkSSL warns when certificate expires soon', async (t) => {
  const socket = createFakeSocket({
    cert: { valid_to: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000).toUTCString() },
    protocol: 'TLSv1.3'
  });

  t.mock.method(tls, 'connect', (options, onConnect) => {
    process.nextTick(onConnect);
    return socket;
  });

  const findings = await checkSSL('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].check, 'certificate_expiry');
  assert.equal(findings[0].status, 'warning');
  assert.equal(findings[0].severity, 'low');
});

test('checkSSL reports HTTPS connection failures', async (t) => {
  const socket = createFakeSocket();

  t.mock.method(tls, 'connect', () => {
    process.nextTick(() => socket.emit('error', { code: 'ECONNREFUSED' }));
    return socket;
  });

  const findings = await checkSSL('https://example.com');

  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'ssl');
  assert.equal(findings[0].check, 'https_availability');
  assert.equal(findings[0].status, 'fail');
  assert.equal(findings[0].severity, 'high');
  assert.match(findings[0].detail, /ECONNREFUSED/);
});

test('checkSSL ignores invalid URLs', async () => {
  const findings = await checkSSL('notaurl');

  assert.deepEqual(findings, []);
});
