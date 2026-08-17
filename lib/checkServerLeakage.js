/**
 * Checks whether the site's Server / X-Powered-By headers reveal
 * specific software versions — useful info for an attacker, so it's
 * worth flagging as a low-severity finding.
 */

async function checkServerLeakage(url) {
  const findings = [];

  let response;
  try {
    response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000)
    });
  } catch (err) {
    return [];
  }

  const serverHeader = response.headers.get('server');
  const poweredByHeader = response.headers.get('x-powered-by');

  // A bare "nginx" or "cloudflare" is fine. A header with a version number
  // attached (e.g. "nginx/1.18.0") is what we want to flag.
  const hasVersionNumber = (value) => value && /\d+\.\d+/.test(value);

  if (hasVersionNumber(serverHeader)) {
    findings.push({
      category: 'server_leakage',
      check: 'Server header',
      status: 'fail',
      severity: 'low',
      detail: `Server header reveals version info: "${serverHeader}".`
    });
  }

  if (poweredByHeader) {
    findings.push({
      category: 'server_leakage',
      check: 'X-Powered-By header',
      status: 'fail',
      severity: 'low',
      detail: `X-Powered-By header reveals backend info: "${poweredByHeader}".`
    });
  }

  return findings;
}

module.exports = { checkServerLeakage };
