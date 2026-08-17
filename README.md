# Website Security Scanner API

A lightweight HTTP API that scans a public website for common security red flags and returns a transparent risk score.

The API is designed for deployment on Vercel and publication on RapidAPI. It does not use AI or hidden scoring logic. Every finding comes from a concrete check such as a missing security header, TLS/certificate problem, exposed sensitive path, outdated CMS fingerprint, or version leakage in response headers.

## Live API

Base URL:

```text
https://website-security-scanner-api.vercel.app
```

The root path `/` is not a website homepage and may return `404`. Use the API routes below.

## Endpoints

### Full Scan

```http
GET /api/scan?url=https://example.com
```

Runs all checks:

- Security headers
- SSL/TLS certificate checks
- Exposed sensitive paths
- CMS version fingerprints
- Server/version leakage

Example:

```bash
curl "https://website-security-scanner-api.vercel.app/api/scan?url=https://example.com"
```

### Quick Scan

```http
GET /api/scan/quick?url=https://example.com
```

Runs only:

- Security headers
- SSL/TLS certificate checks

Example:

```bash
curl "https://website-security-scanner-api.vercel.app/api/scan/quick?url=https://example.com"
```

## Query Parameters

| Name | Required | Description |
|---|---:|---|
| `url` | Yes | Public website URL to scan. Must start with `http://` or `https://`. |

The API blocks localhost, private IP ranges, link-local addresses, and domains that resolve to private/internal IPs to reduce SSRF risk.

## Response Format

Successful responses return:

```json
{
  "url": "https://example.com",
  "scanned_at": "2026-08-17T21:36:57.080Z",
  "risk_score": 63,
  "risk_level": "moderate",
  "findings": [
    {
      "category": "headers",
      "check": "HSTS",
      "status": "missing",
      "severity": "high",
      "detail": "No Strict-Transport-Security header — browsers will not force HTTPS on repeat visits, leaving room for downgrade attacks."
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 2
  }
}
```

Each finding follows this contract:

```json
{
  "category": "headers",
  "check": "HSTS",
  "status": "missing",
  "severity": "high",
  "detail": "Human-readable explanation."
}
```

Error responses return:

```json
{
  "error": "Missing required query parameter: url"
}
```

## Risk Scoring

The score starts at `100`.

| Severity | Deduction |
|---|---:|
| `critical` | `-25` |
| `high` | `-15` |
| `medium` | `-8` |
| `low` | `-3` |
| `info` | `0` |

Risk level mapping:

| Score Range | Risk Level |
|---:|---|
| `80-100` | `low` |
| `50-79` | `moderate` |
| `20-49` | `high` |
| `0-19` | `critical` |

Example: if a site has one high finding, two medium findings, and two low findings:

```text
100 - 15 - 8 - 8 - 3 - 3 = 63
```

The result is:

```text
risk_score: 63
risk_level: moderate
```

## Project Structure

```text
website-security-api/
├── api/
│   ├── scan.js              # GET /api/scan
│   └── scan/
│       └── quick.js         # GET /api/scan/quick
├── lib/
│   ├── checkHeaders.js
│   ├── checkSSL.js
│   ├── checkExposedPaths.js
│   ├── checkCMS.js
│   ├── checkServerLeakage.js
│   ├── httpConfig.js
│   ├── scoring.js
│   └── urlSafety.js
├── scripts/
│   └── smoke-public.js
├── test/
│   └── *.test.js
├── package.json
├── package-lock.json
└── vercel.json
```

## Checks

### Security Headers

Checks whether these headers are present:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`

Missing headers are reported as findings.

### SSL/TLS

Connects directly to port `443` using Node's `tls` module.

Checks:

- certificate trust
- expired certificate
- certificate expiring in fewer than 14 days
- outdated TLS versions such as TLS 1.0 or TLS 1.1
- HTTPS connection availability

### Exposed Paths

Checks common sensitive paths:

- `/.env`
- `/.git/config`
- `/.aws/credentials`
- `/wp-config.php.bak`
- `/admin`

The exposed-path checker includes protections against common false positives:

- It first requests a random nonexistent path. If that returns `200`, the result is marked inconclusive because the site likely uses catch-all routing.
- It skips sensitive-file findings when the response is `text/html`, because that is likely a CDN/WAF decoy page rather than a real exposed file.

### CMS Fingerprints

Looks for lightweight CMS version fingerprints for:

- WordPress
- Joomla
- Drupal

This is a heuristic check, not a full CVE database.

### Server Leakage

Checks:

- `Server`
- `X-Powered-By`

Versioned server headers such as `nginx/1.18.0` are flagged because they reveal specific software versions. Bare server names such as `nginx` are not flagged.

## Local Development

Install dependencies:

```bash
npm install
```

Run tests:

```bash
npm test
```

Run Vercel locally:

```bash
npx vercel dev
```

Then test:

```bash
curl "http://localhost:3000/api/scan?url=https://example.com"
curl "http://localhost:3000/api/scan/quick?url=https://example.com"
```

## Test Coverage

The project includes automated tests for:

- full scan endpoint validation
- quick scan endpoint validation
- SSRF/private URL blocking
- security header detection
- SSL/TLS findings
- exposed-path baseline behavior
- HTML decoy filtering
- CMS version detection
- server leakage detection
- risk scoring
- local fixture-server integration behavior

Run:

```bash
npm test
```

Current verified result:

```text
28 tests passing
0 failing
```

## Public Smoke Tests

Run live checks against a small set of public websites:

```bash
npm run smoke:public
```

Default URLs:

- `https://example.com`
- `https://www.wikipedia.org`
- `https://vercel.com`
- `https://wordpress.org`
- `https://www.cloudflare.com`

You can override the list:

```bash
URLS="https://example.com,https://www.cloudflare.com" npm run smoke:public
```

Live public websites can change headers, redirects, CDN behavior, and bot-protection behavior over time. Treat smoke tests as production sanity checks, not strict pass/fail fixtures.

## Deployment

Deploy to Vercel:

```bash
npx vercel --prod
```

After deployment, verify:

```bash
curl "https://your-project.vercel.app/api/scan?url=https://example.com"
curl "https://your-project.vercel.app/api/scan/quick?url=https://example.com"
curl -i "https://your-project.vercel.app/api/scan"
curl -i "https://your-project.vercel.app/api/scan?url=notaurl"
curl -i "https://your-project.vercel.app/api/scan?url=http://localhost:3000"
```

Expected:

- valid scan URLs return `200`
- missing `url` returns `400`
- invalid URL returns `400`
- localhost/private/internal targets return `400`

## RapidAPI Setup

Use this base URL:

```text
https://website-security-scanner-api.vercel.app
```

Add endpoints:

```text
GET /api/scan
GET /api/scan/quick
```

For both endpoints, add one required query parameter:

```text
url
```

Example test value:

```text
https://example.com
```

Suggested short description:

```text
Scan a public website for common security headers, SSL/TLS issues, exposed sensitive paths, CMS fingerprints, server version leakage, and return a transparent risk score.
```

Suggested disclaimer:

```text
This API performs lightweight security checks and is not a full vulnerability scanner, penetration test, or compliance audit.
```

## Limitations

- This is a basic security scanner, not a full vulnerability scanner.
- CMS detection is based on simple public fingerprints.
- CMS version thresholds are hardcoded and should be updated over time.
- SSL checks use standard HTTPS port `443`.
- Live websites may return different results depending on redirects, CDN region, WAF rules, or bot protection.
- The scanner only reports what it can observe from public HTTP/TLS responses.

## License

Add a license before publishing if you want others to reuse or contribute to the code.
