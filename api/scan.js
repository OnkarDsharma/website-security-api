const { checkSecurityHeaders } = require('../lib/checkHeaders');
const { checkSSL } = require('../lib/checkSSL');
const { checkExposedPaths } = require('../lib/checkExposedPaths');
const { checkCMSVersion } = require('../lib/checkCMS');
const { checkServerLeakage } = require('../lib/checkServerLeakage');
const { calculateRisk } = require('../lib/scoring');

function isValidUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (err) {
    return false;
  }
}

module.exports = async (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    res.status(400).json({ error: 'Missing required query parameter: url' });
    return;
  }

  if (!isValidUrl(targetUrl)) {
    res.status(400).json({ error: 'Invalid url. Must start with http:// or https://' });
    return;
  }

  try {
    // Run all checks in parallel — they're independent of each other,
    // so there's no reason to wait for one before starting the next.
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
      risk_score: score,
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
