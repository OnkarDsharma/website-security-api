/**
 * Checks whether an HTTPS page loads any resources (scripts,
 * stylesheets, images) over plain HTTP. This silently undermines the
 * security guarantee of HTTPS — a mixed-content resource can be
 * intercepted and modified in transit even though the page itself
 * shows the padlock icon.
 */

const { DEFAULT_HEADERS } = require('./httpConfig');

async function checkMixedContent(url) {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (err) {
    return [];
  }

  // Only relevant for HTTPS pages — an HTTP page has no mixed-content concept
  if (parsedUrl.protocol !== 'https:') {
    return [];
  }

  let html;
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      headers: DEFAULT_HEADERS,
      signal: AbortSignal.timeout(8000)
    });
    html = await response.text();
  } catch (err) {
    return [];
  }

  // Look for src="http://..." or href="http://..." references
  const httpResourcePattern = /(?:src|href)=["']http:\/\/[^"']+["']/gi;
  const matches = html.match(httpResourcePattern) || [];

  if (matches.length > 0) {
    const uniqueCount = new Set(matches).size;
    return [{
      category: 'mixed_content',
      check: 'Mixed content',
      status: 'fail',
      severity: 'medium',
      detail: `This HTTPS page loads ${uniqueCount} resource${uniqueCount > 1 ? 's' : ''} over plain HTTP. These resources can be intercepted or modified in transit, undermining the security of the page even though it's served over HTTPS.`
    }];
  }

  return [];
}

module.exports = { checkMixedContent };