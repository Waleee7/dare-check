/* The engine against the real internet. badssl.com exists to be broken in known ways, so each site
   here has a right answer. Needs a network, so it isn't part of `npm test`.

   node scripts/truth.js                  run the engine directly
   node scripts/truth.js https://host     run the same table through a deployed API */
import { scanAddress } from '../lib/scan.js';

const BASE = process.argv[2];

const viaApi = async (url) => {
  const r = await fetch(`${BASE.replace(/\/$/, '')}/api/scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url, fresh: true }) });
  return r.json();
};
const scan = BASE ? viaApi : (url) => scanAddress(url, { fresh: true });

const TABLE = [
  ['expired.badssl.com', { grade: 'F', checks: { https: 'fail', cert: 'fail' }, saw: { https: /expired/ } }],
  ['self-signed.badssl.com', { grade: 'F', checks: { https: 'fail', cert: 'fail' }, saw: { https: /self-signed/ } }],
  ['wrong.host.badssl.com', { grade: 'F', checks: { https: 'fail', cert: 'fail' }, saw: { https: /different domain/ } }],
  ['untrusted-root.badssl.com', { grade: 'F', checks: { https: 'fail', cert: 'fail' } }],
  ['http.badssl.com', { grade: 'F', checks: { https: 'fail' } }],
  ['mixed-script.badssl.com', { checks: { https: 'pass', mixed: 'fail' } }],
  ['mixed.badssl.com', { checks: { https: 'pass', mixed: 'warn' } }],
  ['this-domain-does-not-exist-dare-check-zz.com', { error: /couldn't find a website/ }],
  ['malware.testcategory.com', { grade: 'F', checks: { blocklist: 'fail' } }],
  ['github.com', { grades: ['A', 'B'], checks: { https: 'pass', cert: 'pass', hsts: 'pass', framing: 'pass', nosniff: 'pass', spf: 'pass', dmarc: 'pass', blocklist: 'pass', renewal: 'pass', lock: 'pass', software: 'pass' } }],
  ['wordpress.org', { checks: { https: 'pass', blocklist: 'pass', renewal: 'pass' } }],
  ['docs.github.com', { checks: { https: 'pass', spf: 'pass', dmarc: 'pass', www: 'skip' }, saw: { spf: /github\.com/ } }],
  ['vercel.com', { checks: { https: 'pass', blocklist: 'pass', renewal: 'pass' } }],
  ['ragdoll-riot.vercel.app', { checks: { https: 'pass', spf: 'skip', dmarc: 'skip', renewal: 'skip', lock: 'skip', www: 'skip' } }],
];

let pass = 0, fail = 0;
const say = (ok, name, extra = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ' · ' + extra : ''}`); };

// pace the requests when going through a deployed API, which allows 8 a minute per visitor
const gap = BASE ? 8000 : 250;
for (const [site, want] of TABLE) {
  const t0 = Date.now();
  const r = await scan(site);
  const ms = Date.now() - t0;
  if (want.error) {
    say(!r.ok && want.error.test(r.error || ''), site, r.ok ? `got ${r.grade} ${r.score}` : r.error);
  } else if (!r.ok) {
    say(false, site, r.error);
  } else {
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    const problems = [];
    if (want.grade && r.grade !== want.grade) problems.push(`grade ${r.grade}, wanted ${want.grade}`);
    if (want.grades && !want.grades.includes(r.grade)) problems.push(`grade ${r.grade}, wanted ${want.grades.join('/')}`);
    for (const [id, st] of Object.entries(want.checks ?? {})) if (by[id]?.status !== st) problems.push(`${id}=${by[id]?.status}, wanted ${st} (${by[id]?.saw})`);
    for (const [id, re] of Object.entries(want.saw ?? {})) if (!re.test(by[id]?.saw ?? '')) problems.push(`${id} said "${by[id]?.saw}"`);
    say(!problems.length, site, problems.length ? problems.join(' | ') : `${r.grade} ${r.score} in ${(ms / 1000).toFixed(1)}s, ${r.platform.name}${r.builder ? ', ' + r.builder.name : ''}`);
  }
  await new Promise((res) => setTimeout(res, gap));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
