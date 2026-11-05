/**
 * The only way checkers should make outbound HTTP requests.
 *
 * Plain fetch() with redirect: 'follow' is an SSRF hole: a public URL
 * can 302 to http://169.254.169.254/ or http://127.0.0.1/ and fetch
 * will happily follow it. safeFetch closes that by:
 *
 * - following redirects manually and re-running isSafeUrl() on every hop
 *   (this catches redirects to IP literals, which never hit DNS), and
 * - connecting through an agent whose DNS lookup rejects private
 *   addresses, so DNS rebinding between the check and the connection
 *   doesn't help an attacker either.
 */

const { Agent, fetch: undiciFetch } = require('undici');
const urlSafety = require('./urlSafety');
const { DEFAULT_HEADERS } = require('./httpConfig');

const MAX_REDIRECTS = 5;

const agent = new Agent({ connect: { lookup: urlSafety.safeLookup } });

// Wrapped in an object so tests can mock `client.fetch`.
const client = {
  fetch: (url, options) => undiciFetch(url, { ...options, dispatcher: agent })
};

function blockedTargetError(reason) {
  const err = new Error(`Blocked unsafe target: ${reason}`);
  err.code = 'EBLOCKEDTARGET';
  return err;
}

function isRedirect(response) {
  return response.status >= 300 && response.status < 400 && Boolean(response.headers.get('location'));
}

async function discardBody(response) {
  try {
    await response.body?.cancel?.();
  } catch (err) {
    // nothing useful to do — we're abandoning this response anyway
  }
}

/**
 * @param {string} url
 * @param {object} [options]
 * @param {'follow'|'manual'} [options.redirect='follow']
 * @param {object} [options.headers] merged over DEFAULT_HEADERS
 * @param {number} [options.timeoutMs=8000] covers the whole redirect chain
 */
async function safeFetch(url, { redirect = 'follow', headers = {}, timeoutMs = 8000 } = {}) {
  const signal = AbortSignal.timeout(timeoutMs);
  const requestHeaders = { ...DEFAULT_HEADERS, ...headers };
  let currentUrl = url;

  for (let hop = 0; ; hop += 1) {
    const safety = await urlSafety.isSafeUrl(currentUrl);
    if (!safety.safe) throw blockedTargetError(safety.reason);

    const response = await client.fetch(currentUrl, {
      method: 'GET',
      headers: requestHeaders,
      redirect: 'manual',
      signal
    });

    if (redirect === 'manual' || !isRedirect(response)) {
      return response;
    }

    await discardBody(response);

    if (hop >= MAX_REDIRECTS) {
      throw new Error(`Too many redirects (more than ${MAX_REDIRECTS}).`);
    }

    currentUrl = new URL(response.headers.get('location'), currentUrl).href;
  }
}

module.exports = { safeFetch, client, MAX_REDIRECTS };
