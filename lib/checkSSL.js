/**
 * Connects directly to the site's HTTPS port to inspect the SSL certificate
 * and negotiated TLS protocol version.
 */

const tls = require('tls');

function checkSSL(url) {
  return new Promise((resolve) => {
    let hostname;
    try {
      hostname = new URL(url).hostname;
    } catch (err) {
      resolve([]);
      return;
    }

    const findings = [];

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        family: 4, 
        servername: hostname, // needed for SNI
        timeout: 8000,
        // Important: we still want to inspect the certificate even if it's
        // not trusted by Node's default CA store (e.g. behind a corporate
        // proxy/VPN, or a genuinely misconfigured cert on the target site).
        // We report trust problems as their own finding below instead of
        // aborting the whole check.
        rejectUnauthorized: false
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol(); // e.g. 'TLSv1.2', 'TLSv1.3'

        if (!socket.authorized) {
          findings.push({
            category: 'ssl',
            check: 'certificate_trust',
            status: 'fail',
            severity: 'high',
            detail: `Certificate is not trusted: ${socket.authorizationError}.`
          });
        }

        if (cert && cert.valid_to) {
          const expiryDate = new Date(cert.valid_to);
          const daysLeft = Math.floor((expiryDate - Date.now()) / (1000 * 60 * 60 * 24));

          if (daysLeft < 0) {
            findings.push({
              category: 'ssl',
              check: 'certificate_expiry',
              status: 'fail',
              severity: 'critical',
              detail: 'SSL certificate has expired.'
            });
          } else if (daysLeft < 14) {
            findings.push({
              category: 'ssl',
              check: 'certificate_expiry',
              status: 'warning',
              severity: 'low',
              detail: `Certificate expires in ${daysLeft} days.`
            });
          }
        }

        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          findings.push({
            category: 'ssl',
            check: 'tls_version',
            status: 'fail',
            severity: 'high',
            detail: `Site allows outdated ${protocol}, should be TLS 1.2 or higher.`
          });
        }

        socket.end();
        resolve(findings);
      }
    );

    socket.on('error', (err) => {
      // Site might not support HTTPS at all, or the connection genuinely
      // failed (DNS, connection refused, etc). Include the real reason —
      // makes this debuggable instead of a generic dead end.
      resolve([
        {
          category: 'ssl',
          check: 'https_availability',
          status: 'fail',
          severity: 'high',
          detail: `Could not establish an HTTPS connection: ${err.code || err.message}.`
        }
      ]);
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve([]);
    });
  });
}

module.exports = { checkSSL };
