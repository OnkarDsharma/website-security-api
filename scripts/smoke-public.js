const fullScan = require('../api/scan');
const quickScan = require('../api/scan/quick');

const DEFAULT_URLS = [
  'https://example.com',
  'https://www.wikipedia.org',
  'https://vercel.com',
  'https://wordpress.org',
  'https://www.cloudflare.com'
];

const urls = process.env.URLS
  ? process.env.URLS.split(',').map((url) => url.trim()).filter(Boolean)
  : DEFAULT_URLS;

function createResponse() {
  return {
    statusCode: undefined,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    }
  };
}

async function callHandler(handler, url) {
  const res = createResponse();
  await handler({ query: { url } }, res);
  return res;
}

function summarizeFindings(findings = []) {
  const top = findings
    .slice(0, 4)
    .map((finding) => `${finding.severity}:${finding.category}/${finding.check}`)
    .join(', ');

  return top || 'none';
}

async function main() {
  for (const url of urls) {
    console.log(`\n${url}`);

    const quick = await callHandler(quickScan, url);
    console.log(
      `  quick: status=${quick.statusCode}, risk=${quick.body?.risk_level || 'n/a'}, score=${quick.body?.security_score ?? 'n/a'}, findings=${quick.body?.findings?.length ?? 'n/a'}`
    );
    if (quick.statusCode !== 200) {
      console.log(`  quick error: ${quick.body?.error || 'unknown'}`);
    }

    const full = await callHandler(fullScan, url);
    console.log(
      `  full:  status=${full.statusCode}, risk=${full.body?.risk_level || 'n/a'}, score=${full.body?.security_score ?? 'n/a'}, findings=${full.body?.findings?.length ?? 'n/a'}`
    );
    if (full.statusCode !== 200) {
      console.log(`  full error: ${full.body?.error || 'unknown'}`);
    } else {
      console.log(`  top findings: ${summarizeFindings(full.body.findings)}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
