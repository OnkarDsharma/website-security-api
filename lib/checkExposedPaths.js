/**
 * Tries a small set of known sensitive paths and flags any that
 * respond with 200 instead of a 403/404 — meaning they might be
 * publicly readable when they shouldn't be.
 *
 * Three layers of protection here:
 *
 * 1. Reachability: if the site can't be reached at all, say so plainly
 *    instead of silently returning no findings (which would look like
 *    a clean pass).
 *
 * 2. Baseline check: some sites (SPAs, catch-all routing) return 200
 *    for EVERY path. We test a random nonexistent path first — if
 *    that's also 200, we can't trust this site's status codes at all.
 *
 * 3. Content-type sniffing: some CDNs/WAFs specifically detect probes
 *    for well-known sensitive paths (like /.env) and return a decoy
 *    200 HTML page instead of a real 404, to throw off scanners. A
 *    real exposed .env/.git/credentials file would never legitimately
 *    be served as text/html — so if the response IS html, we treat it
 *    as a decoy, not a real exposure.
 */

const { DEFAULT_HEADERS } = require('./httpConfig');

const SENSITIVE_FILES = [
  { path: '/.env', severity: 'critical', detail: '/.env is publicly accessible : this file often contains database credentials and API keys.' },
  { path: '/.git/config', severity: 'critical', detail: '/.git/config is publicly accessible : the entire git history may be exposed.' },
  { path: '/.aws/credentials', severity: 'critical', detail: '/.aws/credentials is publicly accessible : AWS keys may be exposed.' },
  { path: '/wp-config.php.bak', severity: 'critical', detail: 'A WordPress config backup file is publicly accessible.' }
];

// Not a "file leak" check — just informational, so it doesn't need the
// content-type filter the file checks need.
const INFORMATIONAL_PATHS = [
  { path: '/admin', severity: 'low', detail: 'An /admin path exists and is reachable : not a vulnerability by itself, but worth knowing it is not hidden.' }
];

async function fetchDetails(origin, path) {
  try {
    const response = await fetch(origin + path, {
      method: 'GET',
      redirect: 'manual', // don't follow redirects — a redirect to a login page is fine
      headers: DEFAULT_HEADERS,
      signal: AbortSignal.timeout(6000)
    });
    return {
      status: response.status,
      contentType: response.headers.get('content-type') || ''
    };
  } catch (err) {
    const reason = err.cause?.code || err.cause?.message || err.message;
    return { error: reason };
  }
}

async function checkExposedPaths(baseUrl) {
  let origin;
  try {
    origin = new URL(baseUrl).origin;
  } catch (err) {
    return [];
  }

  // Layer 1: baseline check with a random, guaranteed-nonexistent path.
  const randomPath = `/this-path-should-never-exist-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const baseline = await fetchDetails(origin, randomPath);

  if (baseline.error) {
    return [{
      category: 'exposed_paths',
      check: 'reachability',
      status: 'unreachable',
      severity: 'info',
      detail: `Could not check for exposed files : site unreachable: ${baseline.error}.`
    }];
  }

  if (baseline.status === 200) {
    // This site returns 200 for literally anything — its responses
    // can't tell us whether a sensitive file actually exists. Report
    // this plainly instead of risking false "exposed" findings.
    return [{
      category: 'exposed_paths',
      check: 'baseline',
      status: 'inconclusive',
      severity: 'low',
      detail: 'This site returns HTTP 200 for nonexistent paths (likely catch-all/SPA routing), so exposed-file checks could not be reliably performed.'
    }];
  }

  const findings = [];

  // Layer 2/3: sensitive file checks, filtered by content-type.
  const fileChecks = SENSITIVE_FILES.map(async (item) => {
    const result = await fetchDetails(origin, item.path);
    if (result.error || result.status !== 200) return;

    const looksLikeHtml = result.contentType.includes('text/html');
    if (looksLikeHtml) {
      // Likely a WAF/CDN decoy page, not a real exposed file — skip.
      return;
    }

    findings.push({
      category: 'exposed_paths',
      check: item.path,
      status: 'fail',
      severity: item.severity,
      detail: item.detail
    });
  });

  // Informational paths (no content-type filtering needed).
  const infoChecks = INFORMATIONAL_PATHS.map(async (item) => {
    const result = await fetchDetails(origin, item.path);
    if (!result.error && result.status === 200) {
      findings.push({
        category: 'exposed_paths',
        check: item.path,
        status: 'fail',
        severity: item.severity,
        detail: item.detail
      });
    }
  });

  await Promise.all([...fileChecks, ...infoChecks]);
  return findings;
}

module.exports = { checkExposedPaths };