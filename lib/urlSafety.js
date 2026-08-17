/**
 * Refuses to scan URLs that point at internal/private infrastructure —
 * localhost, private IP ranges, and cloud metadata endpoints. Without
 * this, the API could be used to probe internal infrastructure it was
 * never meant to reach (a known vulnerability class called SSRF).
 */

const dns = require('dns').promises;
const net = require('net');

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;
  if (a === 10) return true;                    // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;       // 192.168.0.0/16
  if (a === 127) return true;                    // loopback
  if (a === 169 && b === 254) return true;       // link-local (covers cloud metadata IP)
  if (a === 0) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
  if (lower.startsWith('fe80')) return true; // link-local
  return false;
}

async function isSafeUrl(urlString) {
  let hostname;
  try {
    hostname = new URL(urlString).hostname;
  } catch (err) {
    return { safe: false, reason: 'Invalid URL.' };
  }

  const lowerHost = hostname.toLowerCase();
  if (lowerHost === 'localhost' || lowerHost.endsWith('.localhost')) {
    return { safe: false, reason: 'Scanning localhost is not allowed.' };
  }

  if (net.isIP(hostname)) {
    const blocked = net.isIP(hostname) === 4 ? isPrivateIPv4(hostname) : isPrivateIPv6(hostname);
    if (blocked) return { safe: false, reason: 'Scanning private/internal IP addresses is not allowed.' };
    return { safe: true };
  }

  try {
    const records = await dns.lookup(hostname, { all: true });
    for (const record of records) {
      const blocked = record.family === 4 ? isPrivateIPv4(record.address) : isPrivateIPv6(record.address);
      if (blocked) {
        return { safe: false, reason: 'This domain resolves to a private/internal IP address, which is not allowed.' };
      }
    }
    return { safe: true };
  } catch (err) {
    // DNS resolution failure isn't a safety issue — let the normal
    // "unreachable" handling deal with it downstream.
    return { safe: true };
  }
}

module.exports = { isSafeUrl };