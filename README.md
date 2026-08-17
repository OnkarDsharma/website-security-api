# Website Security Scanner API

## Project structure

```
website-security-api/
├── api/
│   ├── scan.js          → GET /api/scan?url=      (full scan, all 5 checks)
│   └── scan/
│       └── quick.js     → GET /api/scan/quick?url= (headers + SSL only)
├── lib/
│   ├── checkHeaders.js
│   ├── checkSSL.js
│   ├── checkExposedPaths.js
│   ├── checkCMS.js
│   ├── checkServerLeakage.js
│   └── scoring.js
├── package.json
├── vercel.json
└── .gitignore
```

Each file in `lib/` does exactly one job and returns a plain array of "finding" objects. `api/scan.js` just calls all of them, merges the results, and scores them. If a check ever misbehaves, you know exactly which file to open.

## Step 1 — Install dependencies

On your own machine, in this project folder:

```bash
npm install
```

This installs the Vercel CLI as a dev dependency (used only for local testing) — the API itself has zero runtime dependencies, since Node's built-in `fetch` and `tls` modules do all the work.

## Step 2 — Run it locally

```bash
npx vercel dev
```

The first time, it'll ask you to log in / link a Vercel account (free) — just follow the prompts. It'll then start a local server, usually at `http://localhost:3000`.

## Step 3 — Test it against a real site

In a second terminal, or just in your browser:

```bash
curl "http://localhost:3000/api/scan?url=https://example.com"
```

or open that same URL directly in a browser tab. You should get back the full JSON report. Try the quick endpoint too:

```bash
curl "http://localhost:3000/api/scan/quick?url=https://example.com"
```

Try a few different sites (your own site, a well-known one, one you know runs an old CMS if you have one) to see the findings vary.

## Step 4 — Things worth checking before deploying

- Try a URL missing entirely (`curl "http://localhost:3000/api/scan"`) — should return the 400 error, not crash.
- Try an invalid URL (`?url=notaurl`) — should also return a clean 400.
- Try a site that's slow or unreachable — should time out gracefully within a few seconds, not hang forever.

## Step 5 — Deploy to Vercel

```bash
npx vercel --prod
```

This pushes your code live and gives you a public URL like `https://website-security-api-yourname.vercel.app`. Run the same `curl` tests from Step 3 against that live URL to confirm production works the same as local.

A note on `vercel.json`: I set longer function timeouts (10–15s) since a scan makes several outbound requests. Vercel's free-tier duration limits do change over time, so if deployment complains about the `maxDuration` values, check Vercel's current docs for the Hobby plan's limit and adjust the numbers down if needed.

## Step 6 — Connect it to RapidAPI

Once your Vercel URL is live and tested:
1. Create a RapidAPI provider account
2. Create a new API, set the base URL to your Vercel deployment
3. Add the `GET /scan` endpoint with a `url` query parameter (mark it required)
4. Add the `GET /scan/quick` endpoint the same way
5. Set your pricing tiers
6. Use RapidAPI's built-in test console to call your live endpoint before publishing

## Known limitations of this v1 (fine for launch, worth knowing)

- CMS detection only recognizes WordPress, Joomla, and Drupal, and only via basic HTML fingerprinting — no plugin-level scanning.
- The "old version" cutoffs in `checkCMS.js` are a simple hardcoded list, not a real CVE database — update them occasionally as new major versions ship.
- SSL check connects on port 443 only — sites using SSL on a non-standard port won't be checked correctly.
- No caching — every request does a fresh live scan. Fine at low volume; worth revisiting if you get heavy repeat-URL traffic.
