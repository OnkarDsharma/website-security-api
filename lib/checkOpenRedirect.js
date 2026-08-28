/**
 * Checks for a common open-redirect pattern: appending a well-known
 * redirect parameter (like ?redirect=, ?next=, ?url=) pointing at an
 * external domain, and seeing if the site redirects there without
 * validation. Open redirects are a classic phishing vector — an
 * attacker sends a link that appears to point to a trusted domain but
 * silently redirects to a malicious one.
 *
 * This only tests a handful of very common parameter names. It's a
 * lightweight heuristic, not exhaustive — a real audit would test far
 * more parameter names and injection patterns than is appropriate for
 * an automated, unattended scan like this one.
 */

const { DEFAULT_HEADERS } = require('./httpConfig');

const COMMON_REDIRECT_PARAMS = ['redirect', 'next', 'url', 'return', 'returnUrl'];
const BAIT_DOMAIN = 'https://evil-example-attacker-site.com';

async function checkOpenRedirect(url) {
  let origin;
  try {
    origin = new URL(url).origin;
  } catch (err) {
    return [];
  }

  const checks = COMMON_REDIRECT_PARAMS.map(async (param) => {
    const testUrl = `${origin}/?${param}=${encodeURIComponent(BAIT_DOMAIN)}`;
    try {
      const response = await fetch(testUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: DEFAULT_HEADERS,
        signal: AbortSignal.timeout(6000)
      });

      const location = response.headers.get('location') || '';
      if (response.status >= 300 && response.status < 400 && location.includes('evil-example-attacker-site.com')) {
        return {
          category: 'open_redirect',
          check: `Parameter: ${param}`,
          status: 'fail',
          severity: 'medium',
          detail: `The "${param}" query parameter appears to redirect to an external domain without validation. This can be used in phishing attacks — a link that looks like it points to this trusted site but actually redirects victims elsewhere.`
        };
      }
    } catch (err) {
      // Unreachable or timed out — not evidence of anything, skip silently
    }
    return null;
  });

  const results = await Promise.all(checks);
  return results.filter((r) => r !== null);
}

module.exports = { checkOpenRedirect };