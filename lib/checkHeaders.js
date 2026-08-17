/**
 * Checks a website's response headers for common security headers.
 * Returns an array of finding objects — one per header checked.
 */

const HEADERS_TO_CHECK = [
  {
    name: 'strict-transport-security',
    check: 'HSTS',
    severity: 'high',
    detail: 'No Strict-Transport-Security header — browsers will not force HTTPS on repeat visits, leaving room for downgrade attacks.'
  },
  {
    name: 'content-security-policy',
    check: 'Content-Security-Policy',
    severity: 'medium',
    detail: 'No CSP header found — site is more vulnerable to XSS injection.'
  },
  {
    name: 'x-frame-options',
    check: 'X-Frame-Options',
    severity: 'medium',
    detail: 'No X-Frame-Options header — site can potentially be embedded in an iframe for clickjacking attacks.'
  },
  {
    name: 'x-content-type-options',
    check: 'X-Content-Type-Options',
    severity: 'low',
    detail: 'No X-Content-Type-Options header — browsers may MIME-sniff responses in unexpected ways.'
  },
  {
    name: 'referrer-policy',
    check: 'Referrer-Policy',
    severity: 'low',
    detail: 'No Referrer-Policy header — full URLs may leak to third parties via the Referer header.'
  }
];

const { DEFAULT_HEADERS } = require('./httpConfig');

async function checkSecurityHeaders(url) {
  const findings = [];

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: DEFAULT_HEADERS,
      signal: AbortSignal.timeout(8000)
    });
  } catch (err) {
    return [{
      category: 'headers',
      check: 'reachability',
      status: 'unreachable',
      severity: 'info',
      detail: `Could not check security headers — site unreachable: ${err.code || err.message}.`
    }];
  }

  for (const item of HEADERS_TO_CHECK) {
    const headerValue = response.headers.get(item.name);
    if (!headerValue) {
      findings.push({
        category: 'headers',
        check: item.check,
        status: 'missing',
        severity: item.severity,
        detail: item.detail
      });
    }
  }

  return findings;
}

module.exports = { checkSecurityHeaders };
