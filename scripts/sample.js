/* Builds public/sample.json, the "see a sample report" page, from the real grading engine so the
   sample can never drift from what a scan returns. The business is fictional (.example is a
   reserved name). Run: node scripts/sample.js */
import fs from 'node:fs';
import { evaluate } from '../lib/checks.js';
import { site, NOW } from '../tests/fixtures.js';

const obs = site({
  host: 'www.joesbakery.example',
  days: 54,
  rdap: { expires: '2027-02-14T00:00:00.000Z', registrar: 'GoDaddy.com, LLC', status: ['client transfer prohibited'] },
  wp: { version: '6.4.2', status: 'insecure' },
  www: { host: 'joesbakery.example' },
  headers: {
    server: 'Apache/2.4.41 (Ubuntu)',
    'x-powered-by': 'PHP/7.4.3',
    'x-content-type-options': 'nosniff',
    'set-cookie': ['PHPSESSID=8f2c1a; path=/', 'cookie_notice_accepted=true; expires=Thu, 01 Jan 2027 00:00:00 GMT; path=/; Secure; SameSite=Lax'],
  },
  body: '<!doctype html><html><head><meta name="generator" content="WordPress 6.4.2"><title>Joe\'s Bakery</title></head>' +
    '<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4"></script><script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script><script src="https://connect.facebook.net/en_US/fbevents.js"></script>' +
    '<body><img src="http://www.joesbakery.example/wp-content/uploads/2021/04/cake.jpg"><p>Fresh every morning.</p><form action="/order"><input name="email"></form></body></html>',
  dns: { spf: ['v=spf1 include:_spf.google.com ~all'], dmarc: [], dmarcAt: null, mx: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'] },
});
const report = { ok: true, sample: true, ...evaluate(obs, { now: NOW }) };
fs.writeFileSync(new URL('../public/sample.json', import.meta.url), JSON.stringify(report, null, 1) + '\n');
console.log(`sample: ${report.grade} ${report.score}`, report.counts, report.fixes.map((f) => f.title));
