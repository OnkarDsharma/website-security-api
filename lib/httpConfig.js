/**
 * Shared HTTP request settings used across all checkers.
 *
 * Important: we set a User-Agent that honestly identifies this as a
 * scanner. Requests with NO User-Agent at all are commonly blocked or
 * reset by basic bot-protection/WAFs — an honest, labeled bot UA is
 * often treated better than sending nothing.
 */

const DEFAULT_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (compatible; WebsiteSecurityScannerBot/1.0)'
};

module.exports = { DEFAULT_HEADERS };