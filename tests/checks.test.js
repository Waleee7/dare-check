import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluate, WEIGHTS, gradeOf, detectPlatform, insecureFiles, cookieIssues, unreachable, headerSnippet } from '../lib/checks.js';
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
  assert.deepEqual(r.counts, { pass: 14, warn: 0, fail: 0, skip: 0 });
  assert.equal(r.fixes.length, 0);
  assert.equal(r.capped, false);
});

test('a bare Vercel site loses half credit on five headers and gets one vercel.json fix', () => {
  const r = run(site({ headers: { 'x-vercel-id': 'iad1::abc', server: 'Vercel' } }));
  const s = byId(r);
  for (const id of ['hsts', 'framing', 'nosniff', 'csp', 'permissions']) assert.equal(s[id].status, 'warn', id);
  assert.equal(s.referrer.status, 'pass', 'missing Referrer-Policy falls back to a safe browser default');
  assert.equal(r.score, 87);
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
  assert.match(r.notes.join(' '), /1 check couldn't run/);
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
  assert.match(fix.text, /Squarespace controls these headers/);
  assert.match(headerSnippet('apache', [['X-Frame-Options', 'SAMEORIGIN']]).code, /Header always set X-Frame-Options "SAMEORIGIN"/);
  assert.match(headerSnippet('iis', [['Content-Security-Policy', "frame-ancestors 'self'"]]).code, /value="frame-ancestors 'self'"/);
});

test('firewall challenge pages and server errors get a note', () => {
  const cf = run(site({ headers: { ...STRONG, server: 'cloudflare', 'cf-mitigated': 'challenge' }, https: { status: 403 } }));
  assert.match(cf.notes.join(' '), /challenge page/);
  const err = run(site({ headers: STRONG, https: { status: 503 } }));
  assert.match(err.notes.join(' '), /status 503/);
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
  assert.equal(rows.length, 14);
  for (const [, id, title, pts] of rows) {
    assert.equal(Number(pts), WEIGHTS[id], `${id} points`);
    assert.equal(title.replace(/&#39;|&apos;/g, "'"), INFO[id][0], `${id} title`);
  }
});
