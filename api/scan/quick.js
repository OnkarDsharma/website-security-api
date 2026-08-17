const { checkSecurityHeaders } = require('../../lib/checkHeaders');
const { checkSSL } = require('../../lib/checkSSL');
const { calculateRisk } = require('../../lib/scoring');
const { isSafeUrl } = require('../../lib/urlSafety');
const RAPIDAPI_PROXY_SECRET = process.env.RAPIDAPI_PROXY_SECRET;

function isValidUrl(value) {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch (err) {
    return false;
  }
}

module.exports = async (req, res) => {
  if (RAPIDAPI_PROXY_SECRET && req.headers['x-rapidapi-proxy-secret'] !== RAPIDAPI_PROXY_SECRET) {
    res.status(403).json({ error: 'Direct access is not permitted. Please use this API through RapidAPI.' });
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
    const [headerFindings, sslFindings] = await Promise.all([
      checkSecurityHeaders(targetUrl),
      checkSSL(targetUrl)
    ]);

    const findings = [...headerFindings, ...sslFindings];
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
