/**
 * Refuses to scan URLs that point at internal/private infrastructure —
 * localhost, private IP ranges, and cloud metadata endpoints. Without
 * this, the API could be used to probe internal infrastructure it was
 * never meant to reach (a known vulnerability class called SSRF).
 *
 * Two layers use this module:
 *
 * 1. isSafeUrl() — a fast, up-front check of a URL (used by the API
 *    handlers before a scan starts, and by safeFetch on every redirect hop).
 *
 * 2. safeLookup() — a DNS lookup function handed to the HTTP agent and
 *    the TLS socket. It validates the addresses the connection will
 *    actually use, so a domain that answers with a public IP during
 *    isSafeUrl() and a private IP a moment later (DNS rebinding) is
 *    still blocked.
 */

const dns = require('dns');
const net = require('net');

const BLOCKED = new net.BlockList();

// IPv4 ranges that are not publicly routable (RFC 6890 special-purpose).
[
  ['0.0.0.0', 8],        // "this network"
  ['10.0.0.0', 8],       // private
  ['100.64.0.0', 10],    // carrier-grade NAT
  ['127.0.0.0', 8],      // loopback
  ['169.254.0.0', 16],   // link-local (cloud metadata lives here)
  ['172.16.0.0', 12],    // private
  ['192.0.0.0', 24],     // IETF protocol assignments
  ['192.0.2.0', 24],     // documentation
  ['192.168.0.0', 16],   // private
  ['198.18.0.0', 15],    // benchmarking
  ['198.51.100.0', 24],  // documentation
  ['203.0.113.0', 24],   // documentation
  ['224.0.0.0', 4],      // multicast
  ['240.0.0.0', 4]       // reserved + broadcast
].forEach(([addr, prefix]) => BLOCKED.addSubnet(addr, prefix, 'ipv4'));

// IPv6 ranges. IPv4-mapped addresses (::ffff:a.b.c.d) are matched
// against the IPv4 rules above by BlockList automatically.
[
  ['::', 96],            // unspecified, loopback, IPv4-compatible
  ['64:ff9b::', 96],     // NAT64 — can translate to internal IPv4
  ['100::', 64],         // discard
  ['2001:db8::', 32],    // documentation
  ['2002::', 16],        // 6to4 — embeds an arbitrary IPv4
  ['fc00::', 7],         // unique local
  ['fe80::', 10],        // link-local
  ['ff00::', 8]          // multicast
].forEach(([addr, prefix]) => BLOCKED.addSubnet(addr, prefix, 'ipv6'));

// Test-only escape hatch so fixture servers on 127.0.0.1 can be scanned
// in the test suite. Deliberately not driven by an env var, so it can't
// be switched on by a deployment misconfiguration.
let allowPrivateForTests = false;
function __setAllowPrivateTargetsForTests(value) {
  allowPrivateForTests = Boolean(value);
}

function isBlockedAddress(address) {
  if (allowPrivateForTests) return false;
  const family = net.isIP(address);
  if (family === 4) return BLOCKED.check(address, 'ipv4');
  if (family === 6) return BLOCKED.check(address, 'ipv6');
  return true; // not an IP at all — refuse rather than guess
}

// URL.hostname keeps the brackets around IPv6 literals ("[::1]").
function normalizeHostname(hostname) {
  const lower = hostname.toLowerCase();
  const unbracketed = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;
  return unbracketed.endsWith('.') ? unbracketed.slice(0, -1) : unbracketed;
}

function blockedAddressError(hostname, address) {
  const err = new Error(`${hostname} resolves to a private/internal address (${address}), which is not allowed.`);
  err.code = 'EBLOCKEDADDRESS';
  return err;
}

/**
 * Drop-in replacement for dns.lookup that refuses private/internal
 * addresses. Compatible with net/tls `lookup` and undici's connect.lookup.
 */
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  if (typeof options === 'number') options = { family: options };

  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!addresses || addresses.length === 0) {
      const notFound = new Error(`No addresses found for ${hostname}.`);
      notFound.code = 'ENOTFOUND';
      return callback(notFound);
    }

    const blocked = addresses.find((record) => isBlockedAddress(record.address));
    if (blocked) return callback(blockedAddressError(hostname, blocked.address));

    if (options.all) return callback(null, addresses);
    return callback(null, addresses[0].address, addresses[0].family);
  });
}

async function isSafeUrl(urlString) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch (err) {
    return { safe: false, reason: 'Invalid URL.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { safe: false, reason: 'Only http:// and https:// URLs can be scanned.' };
  }

  if (parsed.username || parsed.password) {
    return { safe: false, reason: 'URLs containing credentials are not allowed.' };
  }

  const hostname = normalizeHostname(parsed.hostname);
  if (!allowPrivateForTests && (hostname === 'localhost' || hostname.endsWith('.localhost'))) {
    return { safe: false, reason: 'Scanning localhost is not allowed.' };
  }

  if (net.isIP(hostname)) {
    if (isBlockedAddress(hostname)) {
      return { safe: false, reason: 'Scanning private/internal IP addresses is not allowed.' };
    }
    return { safe: true };
  }

  try {
    const records = await dns.promises.lookup(hostname, { all: true });
    if (records.some((record) => isBlockedAddress(record.address))) {
      return { safe: false, reason: 'This domain resolves to a private/internal IP address, which is not allowed.' };
    }
    return { safe: true };
  } catch (err) {
    // DNS failure isn't a safety issue by itself — the connection will
    // fail downstream, and safeLookup re-validates if it later resolves.
    return { safe: true };
  }
}

module.exports = {
  isSafeUrl,
  isBlockedAddress,
  safeLookup,
  __setAllowPrivateTargetsForTests
};
