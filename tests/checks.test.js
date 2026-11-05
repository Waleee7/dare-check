import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, WEIGHTS, gradeOf, detectPlatform, insecureFiles, cookieIssues, unreachable, headerSnippet, mergeSpf } from '../lib/checks.js';
import { site, STRONG, NOW, byId } from './fixtures.js';

const run = (o) => evaluate(o, { now: NOW });
const status = (o) => Object.fromEntries(run(o).checks.map((c) => [c.id, c.status]));

test('weights add up to 100 and grades follow the bands', () => {
  assert.equal(Object.values(WEIGHTS).reduce((a, b) => a + b, 0), 100);
  assert.deepEqual([100, 90, 89, 80, 79, 65, 64, 50, 49, 0].map(gradeOf), ['A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'F', 'F']);
});

test('a well-run site gets an A with nothing to fix', () => {
  const r = run(site({ headers: STRONG }));
  assert.equal(r.score, 100);
  assert.equal(r.grade, 'A');
  assert.deepEqual(r.counts, { pass: 20, warn: 0, fail: 0, skip: 0, info: 2 });
  assert.equal(r.fixes.length, 0);
  assert.equal(r.capped, false);
});

test('a bare Vercel site loses half credit on five headers and gets one vercel.json fix', () => {
  const r = run(site({ headers: { 'x-vercel-id': 'iad1::abc', server: 'Vercel' } }));
  const s = byId(r);
  for (const id of ['hsts', 'framing', 'nosniff', 'csp', 'permissions']) assert.equal(s[id].status, 'warn', id);
  assert.equal(s.referrer.status, 'pass', 'missing Referrer-Policy falls back to a safe browser default');
  assert.equal(r.score, 88);
  assert.equal(r.grade, 'B');
  assert.equal(r.platform.id, 'vercel');
  const fix = r.fixes.find((f) => f.file === 'vercel.json');
  assert.ok(fix, 'header fix targets vercel.json');
  const keys = JSON.parse(fix.code).headers[0].headers.map((h) => h.key);
  assert.deepEqual(keys.sort(), ['Content-Security-Policy', 'Permissions-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']);
});

test('no working HTTPS caps the grade at F', () => {
  const o = site({ headers: STRONG, https: { ok: false, error: 'ECONNREFUSED', headers: undefined, cert: null, url: undefined } });
  o.http = { ok: true, status: 200, url: `http://${o.host}/`, chain: [{ url: `http://${o.host}/`, status: 200 }], headers: { ...STRONG }, body: '<p>hi</p>' };
  const r = run(o);
  const s = byId(r);
  assert.equal(r.grade, 'F');
  assert.equal(r.capped, true);
  assert.equal(s.https.status, 'fail');
  assert.match(s.https.saw, /nothing answered on the secure port/);
  assert.equal(s.redirect.status, 'fail');
  assert.equal(s.framing.status, 'pass', 'an http-only site is still judged on its own page headers');
  assert.match(r.notes[0], /capped at F/);
  assert.equal(r.fixes[0].title, 'Turn on HTTPS', 'the biggest fix comes first');
});

test('certificate: expired is F, under a week fails, under three weeks warns', () => {
  const expired = run(site({ headers: STRONG, days: -3, https: { ok: false, error: 'CERT_HAS_EXPIRED' } }));
  assert.equal(expired.grade, 'F');
  assert.match(byId(expired).cert.saw, /^Expired/);
  assert.match(byId(expired).https.saw, /certificate has expired/);
  assert.equal(status(site({ headers: STRONG, days: 3 })).cert, 'fail');
  assert.equal(status(site({ headers: STRONG, days: 10 })).cert, 'warn');
  assert.equal(status(site({ headers: STRONG, days: 60 })).cert, 'pass');
  const wrongName = run(site({ headers: STRONG, https: { ok: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID' } }));
  assert.match(byId(wrongName).cert.saw, /for a different domain/);
});

test('plain http: redirect passes, serving the page fails, port closed passes, timeout is skipped', () => {
  assert.equal(status(site({ headers: STRONG })).redirect, 'pass');
  assert.equal(status(site({ headers: STRONG, http: { next: undefined, status: 200 } })).redirect, 'fail');
  assert.equal(status(site({ headers: STRONG, http: { next: undefined, status: 403 } })).redirect, 'warn');
  assert.equal(status(site({ headers: STRONG, http: { ok: false, error: 'ECONNREFUSED' } })).redirect, 'pass');
  const r = run(site({ headers: STRONG, http: { ok: false, error: 'ETIMEDOUT' } }));
  assert.equal(byId(r).redirect.status, 'skip');
  assert.equal(r.score, 100, 'a skipped check leaves the total instead of costing points');
  assert.match(r.notes.join(' '), /1 check didn't apply or couldn't run/);
});

test('HSTS: short max-age warns with the day count, max-age=0 counts as off', () => {
  const r = byId(run(site({ headers: { ...STRONG, 'strict-transport-security': 'max-age=86400' } })));
  assert.equal(r.hsts.status, 'warn');
  assert.match(r.hsts.saw, /1 day;/);
  assert.match(byId(run(site({ headers: { ...STRONG, 'strict-transport-security': 'max-age=0' } }))).hsts.saw, /switched off/);
});

test('mixed content: http scripts fail, http images warn, upgrade-insecure-requests passes', () => {
  const page = (inner) => `<!doctype html><html><head>${inner}</head></html>`;
  assert.equal(status(site({ headers: STRONG, body: page('<script src="http://cdn.example.net/a.js"></script>') })).mixed, 'fail');
  assert.equal(status(site({ headers: STRONG, body: page('<img src="http://img.example.net/a.png">') })).mixed, 'warn');
  assert.equal(status(site({ headers: STRONG, body: page('<link rel="canonical" href="http://shop.example.com/">') })).mixed, 'pass', 'links that load nothing are fine');
  assert.equal(status(site({ headers: STRONG, body: page('<link rel="stylesheet" href="http://cdn.example.net/a.css">') })).mixed, 'fail');
  const upgraded = { ...STRONG, 'content-security-policy': "default-src 'self'; upgrade-insecure-requests; frame-ancestors 'none'" };
  assert.equal(status(site({ headers: upgraded, body: page('<script src="http://cdn.example.net/a.js"></script>') })).mixed, 'pass');
  assert.deepEqual(insecureFiles('<IMG SRC=http://x.example.net/1.png><video src="https://ok.example.net/v.mp4">'), { active: [], passive: ['http://x.example.net/1.png'] });
});

test('CSP: unsafe-inline warns, nonces pass, report-only and partial policies warn', () => {
  const csp = (v) => byId(run(site({ headers: { ...STRONG, 'content-security-policy': v } }))).csp;
  assert.equal(csp("script-src 'self' 'unsafe-inline'").status, 'warn');
  assert.equal(csp("script-src 'self' 'unsafe-inline' 'nonce-abc123'").status, 'pass');
  assert.equal(csp('default-src *').status, 'warn');
  assert.match(csp('upgrade-insecure-requests').saw, /doesn't limit scripts/);
  const ro = { ...STRONG, 'content-security-policy-report-only': "default-src 'self'" };
  delete ro['content-security-policy'];
  assert.match(byId(run(site({ headers: ro }))).csp.saw, /test mode/);
  const meta = site({ headers: { ...STRONG, 'content-security-policy': undefined }, body: `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">` });
  assert.equal(byId(run(meta)).csp.status, 'pass', 'a <meta> policy counts too');
});

test('framing: frame-ancestors or X-Frame-Options pass, ALLOW-FROM warns', () => {
  const only = (h) => byId(run(site({ headers: { ...STRONG, 'content-security-policy': "default-src 'self'", 'x-frame-options': undefined, ...h } }))).framing.status;
  assert.equal(only({}), 'warn');
  assert.equal(only({ 'x-frame-options': 'SAMEORIGIN' }), 'pass');
  assert.equal(only({ 'x-frame-options': 'ALLOW-FROM https://a.example.net' }), 'warn');
  assert.equal(only({ 'content-security-policy': "default-src 'self'; frame-ancestors 'self'" }), 'pass');
});

test('cookies: missing flags warn and name the cookie, flagged cookies pass', () => {
  const bad = byId(run(site({ headers: { ...STRONG, 'set-cookie': ['PHPSESSID=abc; path=/', 'theme=dark; Secure; SameSite=Lax'] } })));
  assert.equal(bad.cookies.status, 'warn');
  assert.match(bad.cookies.saw, /PHPSESSID: missing Secure, SameSite, HttpOnly/);
  assert.doesNotMatch(bad.cookies.saw, /theme/);
  assert.equal(status(site({ headers: { ...STRONG, 'set-cookie': ['sid=1; Secure; HttpOnly; SameSite=Strict'] } })).cookies, 'pass');
  assert.deepEqual(cookieIssues(['a=1; SameSite=None'], true), [{ name: 'a', miss: ['Secure'] }]);
});

test('leaks: version numbers warn, bare names pass, WordPress gets a functions.php fix', () => {
  assert.equal(status(site({ headers: { ...STRONG, server: 'Apache/2.4.41 (Ubuntu)' } })).leaks, 'warn');
  assert.equal(status(site({ headers: { ...STRONG, server: 'nginx' } })).leaks, 'pass');
  const wp = run(site({ headers: STRONG, body: '<meta name="generator" content="WordPress 6.4.2">' }));
  assert.match(byId(wp).leaks.saw, /WordPress 6\.4\.2/);
  assert.equal(wp.fixes.find((f) => f.checks.includes('leaks')).file, 'functions.php');
});

test('SPF: missing, duplicate and +all fail; ?all warns; ~all, -all and redirect= pass', () => {
  const spf = (records) => status(site({ headers: STRONG, dns: { spf: records } })).spf;
  assert.equal(spf([]), 'fail');
  assert.equal(spf(['v=spf1 -all', 'v=spf1 include:_spf.google.com ~all']), 'fail');
  assert.equal(spf(['v=spf1 +all']), 'fail');
  assert.equal(spf(['v=spf1 all']), 'fail', 'a bare "all" means +all');
  assert.equal(spf(['v=spf1 include:_spf.google.com ?all']), 'warn');
  assert.equal(spf(['v=spf1 include:_spf.google.com']), 'warn');
  assert.equal(spf(['v=spf1 include:spf.protection.outlook.com -all']), 'pass');
  assert.equal(spf(['v=spf1 redirect=_spf.example.com']), 'pass');
});

test('DMARC: missing fails, p=none warns, quarantine/reject pass, inherited records say where', () => {
  const dm = (records, extra = {}) => byId(run(site({ headers: STRONG, dns: { dmarc: records, ...extra } }))).dmarc;
  assert.equal(dm([]).status, 'fail');
  assert.equal(dm(['v=DMARC1; p=none; rua=mailto:a@shop.example.com']).status, 'warn');
  assert.equal(dm(['v=DMARC1; p=reject']).status, 'pass');
  assert.equal(dm(['v=DMARC1; sp=reject']).status, 'fail', 'sp= is not p=');
  assert.match(dm(['v=DMARC1; p=reject'], { dmarcAt: 'example.com' }).saw, /set on example\.com/);
});

test('email fixes follow the mail provider, or lock everything down when there is no mail', () => {
  const google = run(site({ headers: STRONG, dns: { spf: [], dmarc: [] } }));
  assert.equal(google.fixes.find((f) => f.checks.includes('spf')).code, 'v=spf1 include:_spf.google.com ~all');
  const none = run(site({ headers: STRONG, dns: { spf: [], dmarc: [], mx: [] } }));
  assert.equal(none.fixes.find((f) => f.checks.includes('spf')).code, 'v=spf1 -all');
  assert.equal(none.fixes.find((f) => f.checks.includes('dmarc')).code, 'v=DMARC1; p=reject');
  const ms = run(site({ headers: STRONG, dns: { spf: [], mx: ['shop-example-com.mail.protection.outlook.com'] } }));
  assert.match(ms.fixes[0].code, /spf\.protection\.outlook\.com -all/);
  assert.equal(status(site({ headers: STRONG, dns: { ok: false, error: 'ETIMEOUT' } })).spf, 'skip');
});

test('platform detection reads the usual host fingerprints', () => {
  const cases = [
    [{ 'x-vercel-id': 'x' }, 'vercel'], [{ server: 'Netlify' }, 'netlify'], [{ 'x-shopid': '1' }, 'shopify'],
    [{ server: 'Pepyaka/1.19.10' }, 'wix'], [{ server: 'Squarespace' }, 'squarespace'], [{ server: 'DPS/2.0.0' }, 'godaddy'],
    [{ server: 'GitHub.com' }, 'github-pages'], [{ server: 'cloudflare', 'cf-ray': 'x' }, 'cloudflare'],
    [{ server: 'LiteSpeed' }, 'litespeed'], [{ server: 'Apache/2.4.41' }, 'apache'], [{ server: 'nginx/1.18.0' }, 'nginx'],
    [{ server: 'Microsoft-IIS/10.0' }, 'iis'], [{}, 'unknown'],
  ];
  for (const [h, id] of cases) assert.equal(detectPlatform(h), id, JSON.stringify(h));
});

test('locked-down builders get advice instead of code they cannot use', () => {
  const r = run(site({ headers: { server: 'Squarespace' } }));
  const fix = r.fixes.find((f) => f.title === 'Security headers');
  assert.ok(fix && !fix.code);
  assert.match(fix.text, /Squarespace controls these settings/);
  assert.match(headerSnippet('apache', [['X-Frame-Options', 'SAMEORIGIN']]).code, /Header always set X-Frame-Options "SAMEORIGIN"/);
  assert.match(headerSnippet('iis', [['Content-Security-Policy', "frame-ancestors 'self'"]]).code, /value="frame-ancestors 'self'"/);
});

test('firewall challenge pages and server errors get a note', () => {
  const cf = run(site({ headers: { ...STRONG, server: 'cloudflare', 'cf-mitigated': 'challenge' }, https: { status: 403 } }));
  assert.match(cf.caveat, /challenge page/);
  const err = run(site({ headers: STRONG, https: { status: 503 } }));
  assert.match(err.caveat, /status 503/);
  assert.equal(run(site({ headers: STRONG })).caveat, null);
});

test('unreachable() explains why there is nothing to grade', () => {
  const dead = (a, b) => ({ https: { ok: false, error: a }, http: { ok: false, error: b } });
  assert.match(unreachable(dead('ENOTFOUND', 'ENOTFOUND')), /couldn't find a website/);
  assert.match(unreachable(dead('EBLOCKED', 'EBLOCKED')), /private network/);
  assert.match(unreachable(dead('ETIMEDOUT', 'ECONNREFUSED')), /didn't answer/);
  assert.equal(unreachable(site()), null);
});

test('the report carries no internal-only fields and no page body', () => {
  const r = run(site({ headers: { ...STRONG, 'set-cookie': ['sid=1'] }, body: '<script src="http://x.example.net/a.js"></script>' }));
  for (const c of r.checks) for (const k of ['files', 'issues', 'found', 'days', 'body']) assert.ok(!(k in c), `${c.id}.${k}`);
  assert.ok(!JSON.stringify(r).includes('<script'), 'page HTML never leaves the server');
});

test('shared platform addresses skip the email checks and suggest a domain of their own', () => {
  const r = run(site({ host: 'ragdoll-riot.vercel.app', headers: { ...STRONG, 'x-vercel-id': 'x' }, dns: { spf: [], dmarc: [] } }));
  const s = byId(r);
  assert.equal(s.spf.status, 'skip');
  assert.equal(s.dmarc.status, 'skip');
  assert.match(s.spf.saw, /shared vercel\.app address/);
  assert.equal(r.score, 100, 'nothing the owner can fix costs points');
  assert.match(r.notes.join(' '), /domain of your own/);
  assert.ok(!r.fixes.some((f) => f.checks.includes('spf')));
});

test('short HSTS lifetimes read in hours', () => {
  assert.match(byId(run(site({ headers: { ...STRONG, 'strict-transport-security': 'max-age=3600' } }))).hsts.saw, /\(1 hour;/);
});

test('the grade table on the page matches the engine', async () => {
  const fs = await import('node:fs');
  const { INFO } = await import('../lib/checks.js');
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const rows = [...html.matchAll(/<tr data-check="(\w+)"><th scope="row">([^<]+)<\/th><td>[^<]+<\/td><td class="num">(\d+)<\/td><\/tr>/g)];
  assert.equal(rows.length, 20);
  for (const [, id, title, pts] of rows) {
    assert.equal(Number(pts), WEIGHTS[id], `${id} points`);
    assert.equal(title.replace(/&#39;|&apos;/g, "'"), INFO[id][0], `${id} title`);
  }
});

/* ---------------- the checks added in v1 ---------------- */

test('weights cover every scored check, and info rows are never scored', async () => {
  const { GROUPS } = await import('../lib/checks.js');
  const ids = GROUPS.flatMap(([, , list]) => list);
  assert.equal(ids.length, 22);
  for (const id of ids) if (!['dkim', 'thirdparty'].includes(id)) assert.ok(WEIGHTS[id] > 0, id);
  const r = run(site({ headers: STRONG, dkim: { found: [] } }));
  assert.equal(byId(r).dkim.status, 'info');
  assert.equal(byId(r).dkim.weight, 0);
  assert.equal(r.score, 100, 'finding no DKIM key costs nothing');
});

test('an https address that bounces back to http is not secure', () => {
  const r = run(site({ headers: STRONG, https: { url: 'http://shop.example.com/', cert: null } }));
  const s = byId(r);
  assert.equal(s.https.status, 'fail');
  assert.match(s.https.saw, /back to plain http/);
  assert.equal(s.cert.status, 'fail');
  assert.equal(r.grade, 'F');
});

test('forms: plain-http actions fail, https and relative pass, commented-out forms are ignored', () => {
  const form = (body) => byId(run(site({ headers: STRONG, body }))).forms;
  assert.equal(form('<p>no forms</p>').status, 'pass');
  assert.equal(form('<form action="/contact"><input></form>').status, 'pass');
  assert.equal(form('<form action="https://formspree.io/f/x"></form>').status, 'pass');
  const open = form('<form method=post action="http://shop.example.com/login"></form>');
  assert.equal(open.status, 'fail');
  assert.match(open.saw, /http:\/\/shop\.example\.com\/login/);
  assert.equal(form('<!-- <form action="http://old.example.com/"></form> -->').status, 'pass');
  const r = run(site({ headers: STRONG, body: '<form action="http://shop.example.com/x"></form>' }));
  assert.equal(r.fixes.find((f) => f.checks.includes('forms')).code, 'http://shop.example.com/x');
});

test('forms: any form on an http-only page fails', () => {
  const o = site({ headers: STRONG, https: { ok: false, error: 'ECONNREFUSED', headers: undefined, cert: null, url: undefined } });
  o.http = { ok: true, status: 200, url: `http://${o.host}/`, chain: [], headers: { ...STRONG }, body: '<form action="/x"><input type="password"></form>' };
  const f = byId(run(o)).forms;
  assert.equal(f.status, 'fail');
  assert.match(f.saw, /no encryption/);
});

test('www spelling: working passes, cert errors fail, missing warns, timeouts skip, no-variant skips', () => {
  const w = (www) => byId(run(site({ headers: STRONG, www }))).www;
  assert.equal(w({}).status, 'pass');
  assert.equal(w({ applies: false }).status, 'skip');
  assert.equal(w({ ok: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID' }).status, 'fail');
  assert.match(w({ ok: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID' }).saw, /security warning/);
  assert.equal(w({ ok: false, error: 'ENOTFOUND' }).status, 'warn');
  assert.equal(w({ ok: false, error: 'ETIMEDOUT' }).status, 'skip');
  assert.equal(w({ status: 500 }).status, 'warn');
  const r = run(site({ headers: STRONG, www: { ok: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID' } }));
  assert.match(r.fixes.find((f) => f.checks.includes('www')).title, /security warning/);
});

test('blocklist: any filter blocking caps the grade at F and leads the fix list', () => {
  const r = run(site({ headers: STRONG, rep: { cloudflare: 'blocked' } }));
  assert.equal(r.grade, 'F');
  assert.equal(r.capped, true);
  assert.equal(byId(r).blocklist.status, 'fail');
  assert.match(byId(r).blocklist.saw, /Cloudflare's security filter blocks/);
  assert.match(r.notes[0], /capped at F because security filters/);
  assert.equal(r.fixes[0].title, 'Get your site off the blocklist');
  assert.ok(r.fixes[0].links.every((l) => l.href.startsWith('https://')));
  assert.match(r.summary.risks[0].text, /dangerous/);
  const both = byId(run(site({ headers: STRONG, rep: { cloudflare: 'blocked', quad9: 'blocked' } }))).blocklist;
  assert.match(both.saw, /Cloudflare and Quad9's security filters block/);
  assert.equal(byId(run(site({ headers: STRONG, rep: { cloudflare: 'unknown', quad9: 'unknown' } }))).blocklist.status, 'skip');
  assert.equal(byId(run(site({ headers: STRONG, rep: { cloudflare: 'unknown' } }))).blocklist.status, 'pass', 'one clean answer is enough to pass');
});

test('software: WordPress status comes from WordPress.org, old libraries warn with what to update', () => {
  const soft = (o) => byId(run(site({ headers: STRONG, ...o }))).software;
  assert.equal(soft({ wp: { version: '5.8.1', status: 'insecure' } }).status, 'fail');
  assert.match(soft({ wp: { version: '5.8.1', status: 'insecure' } }).saw, /lists this version as insecure/);
  assert.equal(soft({ wp: { version: '6.8', status: 'outdated' } }).status, 'warn');
  assert.equal(soft({ wp: { version: '7.1', status: 'latest' } }).status, 'pass');
  assert.equal(soft({ wp: { version: '9.9', status: null } }).status, 'pass', 'an unknown version is not an accusation');
  const old = '<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>';
  assert.equal(soft({ body: old }).status, 'warn');
  assert.match(soft({ body: old }).saw, /jQuery 1\.12\.4.*CVE-2020-11022/);
  const r = run(site({ headers: STRONG, body: old }));
  const fix = r.fixes.find((f) => f.checks.includes('software'));
  assert.match(fix.code, /jQuery 1\.12\.4 → 3\.5\.0 or newer/);
  assert.equal(soft({ body: '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>' }).status, 'pass');
  assert.match(soft({ body: '<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>' }).saw, /Nothing risky: jQuery 3\.7\.1/);
  const wpFix = run(site({ headers: STRONG, wp: { version: '5.8.1', status: 'insecure' } })).fixes.find((f) => f.checks.includes('software'));
  assert.equal(wpFix.title, 'Update WordPress');
});

test('domain renewal: thresholds, expiry, and registries that say nothing', () => {
  const ren = (days) => byId(run(site({ headers: STRONG, rdap: { expires: new Date(NOW + days * 86400000).toISOString() } }))).renewal;
  assert.equal(ren(400).status, 'pass');
  assert.match(ren(400).saw, /400 days left · registrar: Namecheap/);
  assert.equal(ren(20).status, 'warn');
  assert.equal(ren(5).status, 'fail');
  assert.match(ren(-2).saw, /^Expired/);
  assert.equal(byId(run(site({ headers: STRONG, rdap: { ok: false, error: 'HTTP 404' } }))).renewal.status, 'skip');
  assert.equal(byId(run(site({ headers: STRONG, rdap: { expires: null } }))).renewal.status, 'skip');
  const soon = run(site({ headers: STRONG, rdap: { expires: new Date(NOW + 5 * 86400000).toISOString(), registrar: 'GoDaddy.com, LLC' } }));
  const fix = soon.fixes[0];
  assert.equal(fix.title, 'Renew your domain now', 'an expiring domain goes first');
  assert.match(fix.text, /GoDaddy\.com, LLC/);
  assert.equal(soon.dates.domain, new Date(NOW + 5 * 86400000).toISOString());
});

test('transfer lock: on passes, off warns on big registries, country domains that stay silent skip', () => {
  const lock = (o) => byId(run(site({ headers: STRONG, ...o }))).lock;
  assert.equal(lock({}).status, 'pass');
  assert.equal(lock({ rdap: { status: ['server transfer prohibited', 'active'] } }).status, 'pass');
  assert.equal(lock({ rdap: { status: ['active'] } }).status, 'warn');
  assert.equal(lock({ rdap: { status: [] } }).status, 'skip');
  assert.equal(lock({ rdap: { ok: false } }).status, 'skip');
  assert.equal(lock({ host: 'shop.example.co', rdap: { status: ['active'] } }).status, 'skip');
  const r = run(site({ headers: STRONG, rdap: { status: ['active'] } }));
  assert.equal(r.fixes[0].title, 'Lock your domain');
});

test('a weak existing CSP is never overwritten by the starter snippet', () => {
  const r = run(site({ headers: { ...STRONG, 'content-security-policy': "script-src 'self' 'unsafe-inline'" } }));
  const fix = r.fixes.find((f) => f.title === 'Tighten your Content Security Policy');
  assert.ok(fix);
  assert.ok(!fix.code, 'no snippet that could replace a working policy');
  assert.ok(!r.fixes.some((f) => (f.code || '').includes('Content-Security-Policy')));
  assert.equal(fix.points, 3);
});

test('the starter CSP is offered when there is none, but never promises points it cannot earn', () => {
  const noCsp = { ...STRONG };
  delete noCsp['content-security-policy'];
  const r = run(site({ headers: noCsp }));
  const fix = r.fixes.find((f) => (f.code || '').includes('Content-Security-Policy'));
  assert.ok(fix);
  assert.equal(fix.points, 0, 'the csp check stays a warning after the starter');
  assert.match(fix.text, /won't raise your score/);
  assert.equal(r.score, 97);
  assert.equal(r.potential, null, 'nothing left that would raise the score');
});

test('fix points are real: locked builders earn none, and the promised score adds up', () => {
  const locked = run(site({ headers: { server: 'Squarespace' } }));
  assert.equal(locked.fixes.find((f) => f.title === 'Security headers').points, 0);
  const shop = run(site({ headers: { 'x-shopid': '1' }, dns: { spf: [], dmarc: [] } }));
  assert.equal(shop.platform.id, 'shopify');
  assert.ok(shop.potential.score > shop.score);
  assert.equal(shop.potential.score, shop.score + shop.fixes.reduce((s, f) => s + f.points, 0));
  assert.ok(shop.potential.score < 100, 'locked headers keep it from 100, and the report says so');
});

test('builders detected from the page make locked-down hosts get honest advice', () => {
  const r = run(site({ headers: { server: 'cloudflare' }, body: '<html data-wf-site="abc"><head></head></html>' }));
  assert.equal(r.builder.id, 'webflow');
  assert.match(r.fixes.find((f) => f.title === 'Security headers').text, /Webflow controls these settings/);
  const wp = run(site({ headers: { server: 'cloudflare' }, body: '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>' }));
  assert.equal(wp.builder.id, 'wordpress');
  assert.match(wp.fixes.find((f) => f.title === 'Add the missing security headers').text, /security-headers plugin/);
});

test('subdomains: email findings and fixes point at the main domain', () => {
  const r = run(site({ host: 'blog.example.com', headers: STRONG, dns: { org: 'example.com', spf: ['v=spf1 -all'], spfAt: 'example.com', dmarc: [], dmarcAt: null } }));
  const s = byId(r);
  assert.equal(s.spf.status, 'pass');
  assert.match(s.spf.saw, /set on example\.com/);
  assert.match(s.dmarc.saw, /_dmarc\.example\.com/);
  assert.match(r.fixes.find((f) => f.checks.includes('dmarc')).file, /_dmarc\.example\.com/);
  assert.equal(r.spoof.domain, 'example.com');
});

test('the report says whether email can be spoofed', () => {
  assert.equal(run(site({ headers: STRONG })).spoof, null);
  assert.ok(run(site({ headers: STRONG, dns: { dmarc: [] } })).spoof);
  assert.ok(run(site({ headers: STRONG, dns: { dmarc: ['v=DMARC1; p=none'] } })).spoof);
  assert.equal(run(site({ host: 'x.vercel.app', headers: STRONG, dns: { dmarc: [] } })).spoof, null, 'a shared address has no email of its own');
  assert.equal(run(site({ headers: STRONG, dns: { ok: false } })).spoof, null, "if DNS didn't answer, don't claim anything");
});

test('when the real homepage was out of reach, the report says the grade is rough', () => {
  assert.match(run(site({ headers: STRONG, https: { status: 403 } })).caveat, /turned us away \(status 403\).*rough/);
  assert.match(run(site({ headers: STRONG, https: { status: 429 } })).caveat, /turned us away \(status 429\)/);
  assert.match(run(site({ headers: STRONG, https: { status: 403 }, body: '<script src="/cdn-cgi/challenge-platform/x"></script>' })).caveat, /challenge page/);
  assert.match(run(site({ headers: STRONG, https: { status: 404 } })).caveat, /status 404/);
});

/* ---------------- bugs found by grading real sites ---------------- */

test('merging SPF records keeps every sender, because dropping one breaks their real email', () => {
  const r = run(site({ headers: STRONG, dns: { spf: ['v=spf1 include:amazonses.com ~all', 'v=spf1 include:_spf.google.com ~all'] } }));
  const fix = r.fixes.find((f) => f.checks.includes('spf'));
  assert.equal(fix.title, 'Merge your SPF records into one');
  assert.equal(fix.code, 'v=spf1 include:amazonses.com include:_spf.google.com ~all');
  assert.match(fix.text, /keeps every sender/);
});

test('mergeSpf: drops repeats, follows redirects, and only stays strict if every record was', () => {
  assert.equal(mergeSpf(['v=spf1 ip4:1.2.3.4 -all', 'v=spf1 ip4:1.2.3.4 include:a.example.net -all']), 'v=spf1 ip4:1.2.3.4 include:a.example.net -all');
  assert.equal(mergeSpf(['v=spf1 -all', 'v=spf1 include:a.example.net ~all']), 'v=spf1 include:a.example.net ~all');
  assert.equal(mergeSpf(['v=spf1 redirect=_spf.example.net', 'v=spf1 mx -all']), 'v=spf1 include:_spf.example.net mx ~all');
  assert.equal(mergeSpf(['v=spf1 mx', 'v=spf1 ip4:1.2.3.4 -all']), 'v=spf1 mx ip4:1.2.3.4 ~all');
});

test('the same header sent twice still counts', () => {
  const twice = byId(run(site({ headers: { ...STRONG, 'x-content-type-options': 'nosniff, nosniff', 'x-frame-options': 'DENY, DENY', 'referrer-policy': 'no-referrer, no-referrer' } })));
  assert.equal(twice.nosniff.status, 'pass');
  assert.equal(twice.framing.status, 'pass');
  assert.equal(twice.referrer.saw, 'no-referrer');
});

test('several CSP headers: each is enforced, so any strict one counts', () => {
  const two = (v) => byId(run(site({ headers: { ...STRONG, 'x-frame-options': undefined, 'content-security-policy': v } })));
  const a = two("upgrade-insecure-requests, default-src 'self'; frame-ancestors 'none'");
  assert.equal(a.csp.status, 'pass');
  assert.equal(a.framing.status, 'pass');
  assert.equal(two("default-src *, script-src 'unsafe-inline'").csp.status, 'warn');
  assert.match(two('upgrade-insecure-requests, upgrade-insecure-requests').csp.saw, /^upgrade-insecure-requests \(doesn't limit scripts\)/);
});

test('WordPress is noticed even when a plugin\'s generator tag comes first', () => {
  const body = '<meta name="generator" content="Elementor 4.2.4"><meta name="generator" content="WordPress 6.4.2">';
  const r = run(site({ headers: STRONG, body }));
  assert.equal(r.builder.id, 'wordpress');
  assert.match(byId(r).leaks.saw, /Elementor 4\.2\.4.*WordPress 6\.4\.2/);
});

test('a plugin printing its version gets advice about plugins, not server headers', () => {
  const body = '<script src="/wp-content/x.js"></script><meta name="generator" content="Elementor 4.2.4">';
  const fix = run(site({ headers: STRONG, body })).fixes.find((f) => f.checks.includes('leaks'));
  assert.match(fix.text, /plugin or theme/);
  assert.doesNotMatch(fix.text, /Server and X-Powered-By/);
  assert.ok(!fix.code);
  const hdrFix = run(site({ headers: { ...STRONG, server: 'nginx/1.18.0' } })).fixes.find((f) => f.checks.includes('leaks'));
  assert.match(hdrFix.code, /server_tokens off/);
});

test('hosted builders: cookies and version banners go under "ask support", earning nothing', () => {
  const r = run(site({ headers: { server: 'Pepyaka/1.19', 'x-wix-request-id': '1', 'set-cookie': ['ssr-caching=1'] }, dns: { dmarc: [] } }));
  assert.ok(!r.fixes.some((f) => f.title === 'Flag your cookies'));
  const fix = r.fixes.find((f) => f.title === 'Security headers');
  assert.ok(fix.checks.includes('cookies'));
  assert.equal(fix.points, 0);
  assert.equal(r.fixes[0].title, 'Add a DMARC record', 'what the owner can actually do comes first');
});

test('summary: worst risk first, three at most, plus what is working and the fastest win', () => {
  const r = run(site({ headers: { 'x-vercel-id': 'x' }, dns: { dmarc: [] }, www: { ok: false, error: 'ENOTFOUND' } }));
  assert.equal(r.summary.headline, 'Some real gaps worth fixing.');
  assert.equal(r.summary.risks.length, 3);
  assert.match(r.summary.risks[0].text, /Nothing stops scammers/);
  assert.deepEqual(r.summary.good, ['reputation and upkeep']);
  assert.equal(r.summary.next.title, 'Add a DMARC record', 'most points for the least time');
  assert.equal(r.summary.next.time, 'about 5 minutes');
  assert.equal(r.summary.potential.grade, 'A');
  const clean = run(site({ headers: STRONG }));
  assert.equal(clean.summary.headline, 'The basics are covered.');
  assert.deepEqual(clean.summary.risks, []);
  assert.equal(clean.summary.next, null);
  assert.equal(clean.potential, null);
  assert.equal(clean.summary.good.length, 4);
});

test('no fix or summary leaks internal fields', () => {
  const r = run(site({ headers: {}, dns: { spf: [], dmarc: [] } }));
  for (const f of r.fixes) for (const k of ['mins', 'urgent', 'ids', 'unearned']) assert.ok(!(k in f), `${f.title}.${k}`);
  for (const f of r.fixes) { assert.ok(f.who, f.title); assert.ok(f.time, f.title); }
});
