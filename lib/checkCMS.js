/**
 * Looks at the homepage HTML for CMS fingerprints (WordPress, Drupal, Joomla)
 * and flags version numbers that are known to be old.
 *
 * NOTE: this is a lightweight heuristic check for v1, not a full CVE database.
 * Good enough to be useful; not a substitute for a real vulnerability scanner.
 */

// Minimal "known old" cutoffs — update this list periodically.
const OLD_VERSION_CUTOFFS = {
  wordpress: 6.0,
  joomla: 4.0,
  drupal: 9.0
};

async function checkCMSVersion(url) {
  const findings = [];

  let html;
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000)
    });
    html = await response.text();
  } catch (err) {
    return [];
  }

  // WordPress: usually declares itself in a meta generator tag
  const wpMatch = html.match(/<meta name="generator" content="WordPress ([\d.]+)"/i);
  if (wpMatch) {
    const version = parseFloat(wpMatch[1]);
    findings.push({
      category: 'cms',
      check: 'wordpress_version',
      status: version < OLD_VERSION_CUTOFFS.wordpress ? 'fail' : 'info',
      severity: version < OLD_VERSION_CUTOFFS.wordpress ? 'medium' : 'low',
      detail: version < OLD_VERSION_CUTOFFS.wordpress
        ? `Site runs WordPress ${wpMatch[1]}, which is below the recommended baseline of ${OLD_VERSION_CUTOFFS.wordpress}.`
        : `Site runs WordPress ${wpMatch[1]}.`
    });
  }

  // Joomla
  const joomlaMatch = html.match(/<meta name="generator" content="Joomla! ([\d.]+)"/i);
  if (joomlaMatch) {
    const version = parseFloat(joomlaMatch[1]);
    findings.push({
      category: 'cms',
      check: 'joomla_version',
      status: version < OLD_VERSION_CUTOFFS.joomla ? 'fail' : 'info',
      severity: version < OLD_VERSION_CUTOFFS.joomla ? 'medium' : 'low',
      detail: `Site runs Joomla! ${joomlaMatch[1]}.`
    });
  }

  // Drupal (shows up in headers more often than HTML, but check meta too)
  const drupalMatch = html.match(/Drupal ([\d.]+)/i);
  if (drupalMatch) {
    const version = parseFloat(drupalMatch[1]);
    findings.push({
      category: 'cms',
      check: 'drupal_version',
      status: version < OLD_VERSION_CUTOFFS.drupal ? 'fail' : 'info',
      severity: version < OLD_VERSION_CUTOFFS.drupal ? 'medium' : 'low',
      detail: `Site runs Drupal ${drupalMatch[1]}.`
    });
  }

  return findings;
}

module.exports = { checkCMSVersion };
