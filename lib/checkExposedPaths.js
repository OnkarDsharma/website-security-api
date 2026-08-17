/**
 * Tries a small set of known sensitive paths and flags any that
 * respond with 200 instead of a 403/404 — meaning they might be
 * publicly readable when they shouldn't be.
 *
 * Important edge case: some sites (SPAs, catch-all routing) return
 * HTTP 200 for EVERY path, including ones that don't exist, because
 * the server just serves index.html regardless of the URL. Without
 * accounting for this, we'd wrongly flag those sites as leaking
 * sensitive files. So we first test a random, guaranteed-nonexistent
 * path as a baseline — if that also comes back 200, we know this
 * site's responses can't be trusted to mean "this file exists", and
 * we skip flagging findings from it.
 */

const SENSITIVE_PATHS = [
  { path: '/.env', severity: 'critical', detail: '/.env is publicly accessible — this file often contains database credentials and API keys.' },
  { path: '/.git/config', severity: 'critical', detail: '/.git/config is publicly accessible — the entire git history may be exposed.' },
  { path: '/.aws/credentials', severity: 'critical', detail: '/.aws/credentials is publicly accessible — AWS keys may be exposed.' },
  { path: '/wp-config.php.bak', severity: 'critical', detail: 'A WordPress config backup file is publicly accessible.' },
  { path: '/admin', severity: 'low', detail: 'An /admin path exists and is reachable — not a vulnerability by itself, but worth knowing it is not hidden.' }
];

async function fetchStatus(origin, path) {
  try {
    const response = await fetch(origin + path, {
      method: 'GET',
      redirect: 'manual', // don't follow redirects — a redirect to a login page is fine
      signal: AbortSignal.timeout(6000)
    });
    return response.status;
  } catch (err) {
    return null; // unreachable / timed out — treated as "can't tell"
  }
}

async function checkExposedPaths(baseUrl) {
  let origin;
  try {
    origin = new URL(baseUrl).origin;
  } catch (err) {
    return [];
  }

  // Baseline: a path that cannot possibly exist for real.
  const randomPath = `/this-path-should-never-exist-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const baselineStatus = await fetchStatus(origin, randomPath);

  if (baselineStatus === 200) {
    // This site returns 200 for literally anything — its responses
    // can't tell us whether a sensitive file actually exists. Report
    // this plainly instead of risking false "exposed" findings.
    return [
      {
        category: 'exposed_paths',
        check: 'baseline',
        status: 'inconclusive',
        severity: 'low',
        detail: 'This site returns HTTP 200 for nonexistent paths (likely catch-all/SPA routing), so exposed-file checks could not be reliably performed.'
      }
    ];
  }

  const findings = [];
  const checks = SENSITIVE_PATHS.map(async (item) => {
    const status = await fetchStatus(origin, item.path);
    if (status === 200) {
      findings.push({
        category: 'exposed_paths',
        check: item.path,
        status: 'fail',
        severity: item.severity,
        detail: item.detail
      });
    }
  });

  await Promise.all(checks);
  return findings;
}

module.exports = { checkExposedPaths };