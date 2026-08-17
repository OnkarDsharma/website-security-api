/**
 * Shared HTTP request settings used across all checkers.
 *
 * We set a User-Agent that honestly identifies this as a scanner —
 * requests with NO User-Agent at all are commonly blocked/reset by
 * basic bot-protection, so an honest, labeled one is treated better.
 */

const DEFAULT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (compatible; WebsiteSecurityScannerBot/1.0)'
};

module.exports = { DEFAULT_HEADERS };