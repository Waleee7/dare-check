/* Builds public/sample.json, the "see a sample report" page, from the real grading engine so the
   sample can never drift from what a scan returns. The business is fictional (.example is a
   reserved name). Run: node scripts/sample.js */
import fs from 'node:fs';
import { evaluate } from '../lib/checks.js';
import { site, NOW } from '../tests/fixtures.js';

const obs = site({
  host: 'www.joesbakery.example',
  days: 54,
  headers: {
    server: 'Apache/2.4.41 (Ubuntu)',
    'x-powered-by': 'PHP/7.4.3',
    'x-content-type-options': 'nosniff',
    'set-cookie': ['PHPSESSID=8f2c1a; path=/', 'cookie_notice_accepted=true; expires=Thu, 01 Jan 2027 00:00:00 GMT; path=/; Secure; SameSite=Lax'],
  },
  body: '<!doctype html><html><head><meta name="generator" content="WordPress 6.4.2"><title>Joe\'s Bakery</title></head>' +
    '<body><img src="http://www.joesbakery.example/wp-content/uploads/2021/04/cake.jpg"><p>Fresh every morning.</p></body></html>',
  dns: { spf: ['v=spf1 include:_spf.google.com ~all'], dmarc: [], dmarcAt: null, mx: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'] },
});
const report = { ok: true, sample: true, ...evaluate(obs, { now: NOW }) };
fs.writeFileSync(new URL('../public/sample.json', import.meta.url), JSON.stringify(report, null, 1) + '\n');
console.log(`sample: ${report.grade} ${report.score}`, report.counts, report.fixes.map((f) => f.title));
