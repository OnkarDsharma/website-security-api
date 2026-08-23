const { checkSecurityHeaders } = require('../lib/checkHeaders');
const { checkSSL } = require('../lib/checkSSL');
const { checkExposedPaths } = require('../lib/checkExposedPaths');
const { checkCMSVersion } = require('../lib/checkCMS');
const { checkServerLeakage } = require('../lib/checkServerLeakage');
const { calculateRisk } = require('../lib/scoring');
const { isSafeUrl } = require('../lib/urlSafety');

function isValidUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (err) {
    return false;
  }
}

module.exports = async (req, res) => {
  // This endpoint powers the public landing page demo only — it's not
  // meant for programmatic/API use (that's what the paid RapidAPI
  // endpoints are for). We restrict it to requests that came from our
  // own site, so it can't be used as a free bypass around RapidAPI's
  // billing.
    const origin = req.headers.origin || req.headers.referer || '';
    const allowedOrigins = [
        'https://website-security-scanner-api.vercel.app',
        'http://localhost:3000' // allows local testing via `vercel dev`
    ];
    const isAllowed = allowedOrigins.some((allowed) => origin.startsWith(allowed));
    if (!isAllowed) {
        res.status(403).json({ error: 'This endpoint is only available from the official landing page.' });
        return;
    }

  const targetUrl = req.query.url;

  if (!targetUrl) {
    res.status(400).json({ error: 'Missing required query parameter: url' });
    return;
  }

  if (!isValidUrl(targetUrl)) {
    res.status(400).json({ error: 'Invalid url. Must start with http:// or https://' });
    return;
  }

  const safety = await isSafeUrl(targetUrl);
  if (!safety.safe) {
    res.status(400).json({ error: safety.reason });
    return;
  }

  try {
    const [headerFindings, sslFindings, pathFindings, cmsFindings, serverFindings] =
      await Promise.all([
        checkSecurityHeaders(targetUrl),
        checkSSL(targetUrl),
        checkExposedPaths(targetUrl),
        checkCMSVersion(targetUrl),
        checkServerLeakage(targetUrl)
      ]);

    const findings = [
      ...headerFindings,
      ...sslFindings,
      ...pathFindings,
      ...cmsFindings,
      ...serverFindings
    ];

    const { score, riskLevel, summary } = calculateRisk(findings);

    res.status(200).json({
      url: targetUrl,
      scanned_at: new Date().toISOString(),
      security_score: score,
      risk_level: riskLevel,
      findings,
      summary
    });
  } catch (err) {
    res.status(500).json({
      error: 'Scan failed unexpectedly.',
      detail: err.message
    });
  }
};