/**
 * A simple per-IP daily rate limiter for the free public landing page.
 *
 * IMPORTANT LIMITATION: this uses in-memory storage, which resets
 * whenever the serverless function cold-starts, and isn't shared
 * across multiple concurrent instances. This means it's a soft
 * deterrent against casual overuse, not a hard, precise limit — under
 * real load, the true limit could be somewhat higher than the number
 * below. That's an acceptable tradeoff for a free demo tool. If this
 * ever needs to be precise (e.g. abuse becomes a real problem), swap
 * this for a shared store like Vercel KV or Upstash Redis.
 */

const DAILY_LIMIT = 10;
const WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours

const requestLog = new Map(); // ip -> array of timestamps

function checkRateLimit(ip) {
  const now = Date.now();
  const timestamps = (requestLog.get(ip) || []).filter((t) => now - t < WINDOW_MS);

  if (timestamps.length >= DAILY_LIMIT) {
    const oldestInWindow = timestamps[0];
    const resetsInMs = WINDOW_MS - (now - oldestInWindow);
    return {
      allowed: false,
      resetsInMinutes: Math.ceil(resetsInMs / 60000)
    };
  }

  timestamps.push(now);
  requestLog.set(ip, timestamps);
  return { allowed: true, remaining: DAILY_LIMIT - timestamps.length };
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

module.exports = { checkRateLimit, getClientIp };