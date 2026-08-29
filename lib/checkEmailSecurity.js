/**
 * Checks whether a domain has SPF and DMARC DNS records set up.
 * Without these, anyone can send emails that appear to come from this
 * domain — a common phishing/spoofing vector that most basic scanners
 * miss entirely, since it's a DNS check, not an HTTP check.
 *
 * DKIM isn't checked here — DKIM records live at a selector-specific
 * subdomain (e.g. google._domainkey.example.com) that isn't
 * discoverable without knowing the selector in advance, so it can't
 * be reliably checked without more information than we have.
 */

const dns = require('dns').promises;

async function checkEmailSecurity(url) {
  let hostname;
  try {
    hostname = new URL(url).hostname;
  } catch (err) {
    return [];
  }

  const findings = [];

  // SPF: published as a TXT record on the domain itself, starting with "v=spf1"
  try {
    const txtRecords = await dns.resolveTxt(hostname);
    const hasSpf = txtRecords.some((record) => record.join('').startsWith('v=spf1'));
    if (!hasSpf) {
      findings.push({
        category: 'email_security',
        check: 'SPF',
        status: 'missing',
        severity: 'medium',
        detail: 'No SPF record found : without this, mail servers cannot verify whether an email claiming to be from this domain was actually sent by an authorized server, making the domain easier to spoof in phishing emails.'
      });
    }
  } catch (err) {
    // No TXT records at all, or DNS lookup failed — treat the same as missing SPF
    findings.push({
      category: 'email_security',
      check: 'SPF',
      status: 'missing',
      severity: 'medium',
      detail: 'No SPF record found : without this, mail servers cannot verify whether an email claiming to be from this domain was actually sent by an authorized server, making the domain easier to spoof in phishing emails.'
    });
  }

  // DMARC: published as a TXT record at _dmarc.<domain>
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${hostname}`);
    const hasDmarc = dmarcRecords.some((record) => record.join('').startsWith('v=DMARC1'));
    if (!hasDmarc) {
      findings.push({
        category: 'email_security',
        check: 'DMARC',
        status: 'missing',
        severity: 'medium',
        detail: 'No DMARC record found, this tells receiving mail servers what to do with emails that fail authentication checks. Without it, spoofed emails impersonating this domain are more likely to reach inboxes instead of being blocked.'
      });
    }
  } catch (err) {
    findings.push({
      category: 'email_security',
      check: 'DMARC',
      status: 'missing',
      severity: 'medium',
      detail: 'No DMARC record found, this tells receiving mail servers what to do with emails that fail authentication checks. Without it, spoofed emails impersonating this domain are more likely to reach inboxes instead of being blocked.'
    });
  }

  return findings;
}

module.exports = { checkEmailSecurity };