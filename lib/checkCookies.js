/**
 * Checks cookies set by the site for missing security attributes.
 * Missing Secure/HttpOnly/SameSite flags are a classic session
 * hijacking vector — e.g. a missing HttpOnly flag lets a successful
 * XSS attack steal a session cookie directly via JavaScript.
 */

const { DEFAULT_HEADERS } = require('./httpConfig');

async function checkCookies(url) {
  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: DEFAULT_HEADERS,
      signal: AbortSignal.timeout(8000)
    });
  } catch (err) {
    return [];
  }

  // getSetCookie() is the standard way to get all Set-Cookie headers
  // (there can be multiple); fall back to a single header read if
  // the runtime doesn't support it.
  const rawCookies = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);

  if (rawCookies.length === 0) {
    return []; // no cookies set — nothing to check
  }

  const findings = [];

  rawCookies.forEach((cookie) => {
    const cookieName = cookie.split('=')[0].trim();
    const lowerCookie = cookie.toLowerCase();

    if (!lowerCookie.includes('secure')) {
      findings.push({
        category: 'cookies',
        check: `Cookie: ${cookieName}`,
        status: 'missing',
        severity: 'medium',
        detail: `The "${cookieName}" cookie is missing the Secure flag — it could be transmitted over an unencrypted HTTP connection, exposing it to interception.`
      });
    }

    if (!lowerCookie.includes('httponly')) {
      findings.push({
        category: 'cookies',
        check: `Cookie: ${cookieName}`,
        status: 'missing',
        severity: 'medium',
        detail: `The "${cookieName}" cookie is missing the HttpOnly flag — it can be read by JavaScript, making it stealable via a successful XSS attack.`
      });
    }

    if (!lowerCookie.includes('samesite')) {
      findings.push({
        category: 'cookies',
        check: `Cookie: ${cookieName}`,
        status: 'missing',
        severity: 'low',
        detail: `The "${cookieName}" cookie is missing the SameSite attribute — it may be sent along with cross-site requests, which can enable CSRF attacks.`
      });
    }
  });

  return findings;
}

module.exports = { checkCookies };