/**
 * Checks for a dangerous CORS misconfiguration: a site that allows
 * requests from ANY origin (Access-Control-Allow-Origin: *) while
 * also allowing credentials. That combination lets any malicious
 * website make authenticated requests to this site on a victim's
 * behalf — genuinely exploitable, and a common mistake in APIs
 * specifically (relevant to vibecoder-built projects).
 */

const { DEFAULT_HEADERS } = require('./httpConfig');

async function checkCORS(url) {
  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        ...DEFAULT_HEADERS,
        // Simulate a cross-origin request from an arbitrary attacker-controlled site
        Origin: 'https://evil-example-attacker-site.com'
      },
      signal: AbortSignal.timeout(8000)
    });
  } catch (err) {
    return [];
  }

  const allowOrigin = response.headers.get('access-control-allow-origin');
  const allowCredentials = response.headers.get('access-control-allow-credentials');

  if (allowOrigin === '*' && allowCredentials === 'true') {
    return [{
      category: 'cors',
      check: 'CORS misconfiguration',
      status: 'fail',
      severity: 'critical',
      detail: 'This site sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. This combination lets any website make authenticated, credentialed requests to this site on a visitor\'s behalf — a serious and exploitable misconfiguration.'
    }];
  }

  if (allowOrigin === '*') {
    return [{
      category: 'cors',
      check: 'CORS wide open',
      status: 'warning',
      severity: 'low',
      detail: 'This site allows requests from any origin (Access-Control-Allow-Origin: *). This is only a real risk if the site also allows credentials, which it currently does not — but it\'s worth confirming this is intentional.'
    }];
  }

  return [];
}

module.exports = { checkCORS };