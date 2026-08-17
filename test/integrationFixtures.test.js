const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');

const { checkCMSVersion } = require('../lib/checkCMS');
const { checkExposedPaths } = require('../lib/checkExposedPaths');
const { checkSecurityHeaders } = require('../lib/checkHeaders');
const { checkServerLeakage } = require('../lib/checkServerLeakage');

function createFixtureServer(mode = 'default') {
  const server = http.createServer((req, res) => {
    const path = new URL(req.url, 'http://fixture.local').pathname;

    if (mode === 'exposed-env') {
      if (path === '/.env') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('DATABASE_URL=postgres://example');
        return;
      }

      res.writeHead(404);
      res.end('not found');
      return;
    }

    if (mode === 'html-decoy') {
      if (path === '/.env') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<html>blocked</html>');
        return;
      }

      res.writeHead(404);
      res.end('not found');
      return;
    }

    if (mode === 'spa-catchall') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html>app shell</html>');
      return;
    }

    if (path === '/secure-headers') {
      res.writeHead(200, {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'no-referrer'
      });
      res.end('secure');
      return;
    }

    if (path === '/missing-headers') {
      res.writeHead(200);
      res.end('missing headers');
      return;
    }

    if (path === '/old-wordpress') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><meta name="generator" content="WordPress 5.9.9"></html>');
      return;
    }

    if (path === '/server-leakage') {
      res.writeHead(200, {
        Server: 'nginx/1.18.0',
        'X-Powered-By': 'Express'
      });
      res.end('leaky');
      return;
    }

    if (path === '/bare-server') {
      res.writeHead(200, { Server: 'nginx' });
      res.end('bare');
      return;
    }

    res.writeHead(404);
    res.end('not found');
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(done))
      });
    });
  });
}

test('fixture server verifies header checker behavior', async (t) => {
  const fixture = await createFixtureServer();
  t.after(fixture.close);

  const missingFindings = await checkSecurityHeaders(`${fixture.baseUrl}/missing-headers`);
  assert.deepEqual(
    missingFindings.map((finding) => finding.check).sort(),
    [
      'Content-Security-Policy',
      'HSTS',
      'Referrer-Policy',
      'X-Content-Type-Options',
      'X-Frame-Options'
    ]
  );

  const secureFindings = await checkSecurityHeaders(`${fixture.baseUrl}/secure-headers`);
  assert.deepEqual(secureFindings, []);
});

test('fixture server verifies exposed-path baseline, leak, and decoy behavior', async (t) => {
  const exposedFixture = await createFixtureServer('exposed-env');
  const decoyFixture = await createFixtureServer('html-decoy');
  const spaFixture = await createFixtureServer('spa-catchall');
  t.after(exposedFixture.close);
  t.after(decoyFixture.close);
  t.after(spaFixture.close);

  const exposedFindings = await checkExposedPaths(exposedFixture.baseUrl);
  assert.deepEqual(exposedFindings.map((finding) => finding.check), ['/.env']);
  assert.equal(exposedFindings[0].severity, 'critical');

  const decoyFindings = await checkExposedPaths(decoyFixture.baseUrl);
  assert.deepEqual(decoyFindings, []);

  const spaFindings = await checkExposedPaths(spaFixture.baseUrl);
  assert.equal(spaFindings.length, 1);
  assert.equal(spaFindings[0].check, 'baseline');
  assert.equal(spaFindings[0].status, 'inconclusive');
});

test('fixture server verifies CMS and server leakage behavior', async (t) => {
  const fixture = await createFixtureServer();
  t.after(fixture.close);

  const cmsFindings = await checkCMSVersion(`${fixture.baseUrl}/old-wordpress`);
  assert.equal(cmsFindings.length, 1);
  assert.equal(cmsFindings[0].check, 'wordpress_version');
  assert.equal(cmsFindings[0].status, 'fail');
  assert.equal(cmsFindings[0].severity, 'medium');

  const leakyFindings = await checkServerLeakage(`${fixture.baseUrl}/server-leakage`);
  assert.deepEqual(
    leakyFindings.map((finding) => finding.check),
    ['Server header', 'X-Powered-By header']
  );

  const bareFindings = await checkServerLeakage(`${fixture.baseUrl}/bare-server`);
  assert.deepEqual(bareFindings, []);
});
