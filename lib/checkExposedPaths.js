/**
 * Tries a small set of known sensitive paths and flags any that
 * respond with 200 instead of a 403/404 — meaning they might be
 * publicly readable when they shouldn't be.
 */

const SENSITIVE_PATHS = [
  { path: '/.env', severity: 'critical', detail: '/.env is publicly accessible — this file often contains database credentials and API keys.' },
  { path: '/.git/config', severity: 'critical', detail: '/.git/config is publicly accessible — the entire git history may be exposed.' },
  { path: '/.aws/credentials', severity: 'critical', detail: '/.aws/credentials is publicly accessible — AWS keys may be exposed.' },
  { path: '/wp-config.php.bak', severity: 'critical', detail: 'A WordPress config backup file is publicly accessible.' },
  { path: '/admin', severity: 'low', detail: 'An /admin path exists and is reachable — not a vulnerability by itself, but worth knowing it is not hidden.' }
];

async function checkExposedPaths(baseUrl) {
  const findings = [];
  let origin;
  try {
    origin = new URL(baseUrl).origin;
  } catch (err) {
    return [];
  }

  const checks = SENSITIVE_PATHS.map(async (item) => {
    try {
      const response = await fetch(origin + item.path, {
        method: 'GET',
        redirect: 'manual', // don't follow redirects — a redirect to a login page is fine
        signal: AbortSignal.timeout(6000)
      });

      if (response.status === 200) {
        findings.push({
          category: 'exposed_paths',
          check: item.path,
          status: 'fail',
          severity: item.severity,
          detail: item.detail
        });
      }
    } catch (err) {
      // Unreachable path = not exposed, nothing to flag
    }
  });

  await Promise.all(checks);
  return findings;
}

module.exports = { checkExposedPaths };
