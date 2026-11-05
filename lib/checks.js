/* Turns raw observations (from inspect.js) into the graded report. Pure, no network, so the tests
   can feed it any site they like. Weights add up to 100: a pass earns the full weight, a warning
   half, a fail nothing. Checks that couldn't run ("skip") leave the total instead of costing points,
   and "info" rows tell the owner something without ever being scored. */
import { parsePage, detectBuilder, BUILDERS, libraries, thirdParties, insecureFiles } from './html.js';
import { sharedSuffix } from './domains.js';
import { summarize } from './summary.js';

export { insecureFiles, sharedSuffix };

export const WEIGHTS = {
  https: 12, redirect: 6, cert: 7, hsts: 8, mixed: 4, forms: 3, www: 2,
  framing: 6, nosniff: 3, csp: 6, referrer: 1, permissions: 2, cookies: 3, leaks: 3,
  spf: 7, dmarc: 9,
  blocklist: 6, software: 5, renewal: 5, lock: 2,
};
const CREDIT = { pass: 1, warn: 0.5, fail: 0 };

export const GROUPS = [
  ['connection', 'Connection', ['https', 'redirect', 'cert', 'hsts', 'mixed', 'forms', 'www']],
  ['browser', 'Browser protections', ['framing', 'nosniff', 'csp', 'referrer', 'permissions', 'cookies', 'leaks']],
  ['email', 'Email', ['spf', 'dmarc', 'dkim']],
  ['trust', 'Reputation and upkeep', ['blocklist', 'software', 'renewal', 'lock', 'thirdparty']],
];

export const INFO = {
  https: ['Secure connection (HTTPS)', 'Without it, anyone on the same Wi-Fi can read or change what your customers see and type.'],
  redirect: ['Sends visitors to the secure version', 'People who type your address without https:// should still land on the secure site.'],
  cert: ['Security certificate is current', 'When it expires, browsers show a full-page warning and most visitors leave.'],
  hsts: ['Browsers remember to use HTTPS (HSTS)', 'Stops a trick on public Wi-Fi that keeps visitors on the insecure version of your site.'],
  mixed: ['No insecure files on the secure page', 'Scripts or images loaded over plain http can be swapped by an attacker, and browsers block some of them.'],
  forms: ['Forms send securely', 'Anything typed into a form that posts over plain http can be read along the way, and browsers warn people before sending it.'],
  www: ['The www address works too', 'Plenty of people still type www. If that version is broken or shows a security warning, they think your whole site is.'],
  framing: ["Can't be hidden inside another site", 'Stops scam pages from loading your site invisibly and tricking people into clicking your buttons.'],
  nosniff: ["Files can't pretend to be scripts (nosniff)", 'Stops browsers from running a file as code when it claims to be something else.'],
  csp: ['Content Security Policy', "A list of where your site's scripts may come from. If bad code sneaks in, the browser refuses to run it."],
  referrer: ['Page addresses stay private (Referrer-Policy)', 'Controls how much of your page address is shared when a visitor clicks a link to another site.'],
  permissions: ['Camera, mic and location locked (Permissions-Policy)', 'Makes sure nothing embedded in your site can ask visitors for their camera, microphone or location.'],
  cookies: ['Cookies are protected', 'Cookies can hold logins and carts. The Secure, HttpOnly and SameSite flags keep them from being stolen.'],
  leaks: ["Doesn't advertise software versions", "Showing exact versions (like 'Apache 2.4.41') tells attackers which known holes to try."],
  spf: ['Email sender list (SPF)', 'Tells inboxes which servers may send email as your domain. Without it, scammers can send fake invoices that look like yours.'],
  dmarc: ['Email spoofing protection (DMARC)', 'Tells inboxes what to do with fake email that uses your domain: let it in, send it to junk, or reject it.'],
  dkim: ['Email signing (DKIM)', "A signature that proves your email really came from you. Not scored, because DKIM keys can be named anything and we can only look in the usual places."],
  blocklist: ['Not flagged as dangerous', 'Security filters block sites known for malware or scams. A hacked site can end up there without its owner ever finding out.'],
  software: ['No known-risky software versions', 'Old versions of WordPress and common code libraries have published security holes that attackers scan for.'],
  renewal: ["Domain name isn't about to expire", 'If your domain lapses, your site and email stop working, and someone else can buy the name.'],
  lock: ['Domain is locked against transfers', 'A transfer lock stops anyone who gets into your account, or fools your registrar, from quietly moving your domain away.'],
  thirdparty: ["Other companies' code on your homepage", 'Scripts from other companies can read what people type on your page. Not scored, because most sites need some, but you should know who is on the list.'],
};

export const PLATFORMS = {
  vercel: 'Vercel', netlify: 'Netlify', cloudflare: 'Cloudflare', shopify: 'Shopify', wix: 'Wix', squarespace: 'Squarespace',
  godaddy: 'GoDaddy Website Builder', 'github-pages': 'GitHub Pages', apache: 'Apache', litespeed: 'LiteSpeed', nginx: 'Nginx',
  iis: 'Microsoft IIS', aws: 'Amazon Web Services', google: 'Google', unknown: 'Not detected',
};
// hosted builders that don't let owners add their own response headers
const LOCKED = new Set(['shopify', 'wix', 'squarespace', 'godaddy', 'github-pages', 'webflow', 'framer', 'weebly', 'duda']);

const NET = {
  CERT_HAS_EXPIRED: 'the certificate has expired',
  CERT_NOT_YET_VALID: "the certificate isn't valid yet",
  DEPTH_ZERO_SELF_SIGNED_CERT: "the certificate is self-signed, so browsers don't trust it",
  SELF_SIGNED_CERT_IN_CHAIN: "the certificate chain includes a self-signed certificate, so browsers don't trust it",
  ERR_TLS_CERT_ALTNAME_INVALID: 'the certificate is for a different domain',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the certificate chain is incomplete',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'the certificate chain is incomplete',
  UNABLE_TO_GET_ISSUER_CERT: 'the certificate chain is incomplete',
  ECONNREFUSED: 'nothing answered on the secure port (443)',
  ECONNRESET: 'the connection was dropped',
  ETIMEDOUT: 'it took too long to answer',
  ENOTFOUND: "the domain name doesn't exist",
  EAI_AGAIN: "the domain name couldn't be looked up",
  EREDIRECTS: 'it redirects in a loop',
  EREDIRECT: 'it redirects somewhere DARE CHECK can\'t follow',
  EBLOCKED: 'it points to a private network address',
  EPROTO: 'the secure connection failed',
  ERR_SSL_UNSUPPORTED_PROTOCOL: 'it only offers old encryption that browsers have dropped',
  ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION: 'it only offers old encryption that browsers have dropped',
};
const CERT_CODES = new Set(Object.keys(NET).filter((k) => /CERT|SIGN/.test(k)));
const why = (code) => NET[code] || 'the connection failed';
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const clip = (s, n = 160) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const span = (secs) => (secs < 86400 ? plural(Math.max(1, Math.round(secs / 3600)), 'hour') : plural(Math.round(secs / 86400), 'day'));
const fmtDate = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });

// header value, with repeated headers joined. The same value sent twice (a common config slip) is still one value.
function hdr(res, name) {
  const raw = res?.headers?.[name];
  const v = Array.isArray(raw) ? raw.join(', ') : raw ?? '';
  const parts = v.split(/,\s*/);
  return parts.length > 1 && parts.every((p) => p === parts[0]) ? parts[0] : v;
}

// the page whose headers get judged: the secure one, or the plain-http page on an http-only site
function pageOf(o) {
  if (o.https.headers) return o.https;
  if (o.http.ok && !o.http.next && o.http.status < 400) return o.http;
  return null;
}

function directives(policy) {
  const out = {};
  for (const part of policy.split(';')) {
    const [name, ...rest] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in out)) out[name.toLowerCase()] = rest.join(' ');
  }
  return out;
}
// several CSP headers arrive comma-joined; browsers enforce each one, so each one counts
const policies = (v) => v.split(',').map(directives);

const SESSIONISH = /sess|sid\b|auth|token|login|logged_in|remember|csrf|xsrf/i;
export function cookieIssues(list = [], secureSite = true) {
  const out = [];
  for (const raw of list) {
    const [pair, ...attrs] = raw.split(';');
    const name = pair.split('=')[0].trim();
    const a = attrs.map((s) => s.trim().toLowerCase());
    const has = (k) => a.some((x) => x === k || x.startsWith(k + '='));
    const same = a.find((x) => x.startsWith('samesite='))?.split('=')[1]?.trim();
    const miss = [];
    if (secureSite && !has('secure')) miss.push('Secure');
    if (!same) miss.push('SameSite');
    else if (same === 'none' && !has('secure') && !miss.includes('Secure')) miss.push('Secure (needed with SameSite=None)');
    if (SESSIONISH.test(name) && !has('httponly')) miss.push('HttpOnly');
    if (miss.length) out.push({ name, miss });
  }
  return out;
}

export function detectPlatform(h = {}) {
  const v = (k) => String(Array.isArray(h[k]) ? h[k][0] : h[k] ?? '').toLowerCase();
  const server = v('server');
  if (h['x-vercel-id'] || server === 'vercel') return 'vercel';
  if (h['x-nf-request-id'] || server.includes('netlify')) return 'netlify';
  if (h['x-shopid'] || h['x-shopify-stage'] || v('powered-by').includes('shopify')) return 'shopify';
  if (h['x-wix-request-id'] || server.startsWith('pepyaka')) return 'wix';
  if (server.includes('squarespace')) return 'squarespace';
  if (server.startsWith('dps/')) return 'godaddy';
  if (server.includes('github.com')) return 'github-pages';
  if (server === 'cloudflare' || h['cf-ray']) return 'cloudflare';
  if (server.startsWith('litespeed')) return 'litespeed';
  if (server.startsWith('apache')) return 'apache';
  if (server.startsWith('nginx') || server.startsWith('openresty')) return 'nginx';
  if (server.startsWith('microsoft-iis')) return 'iis';
  if (h['x-amz-cf-id'] || server === 'amazons3' || server === 'cloudfront') return 'aws';
  if (server === 'ghs' || server === 'gws' || server.startsWith('google')) return 'google';
  return 'unknown';
}

/* ---------------- the checks ---------------- */

const NO_SECURE = { status: 'fail', saw: 'There is no working secure version of the site.' };
const NO_PAGE = { status: 'skip', saw: "Couldn't load the homepage to check this." };
const DAY = 86400000;
const isPlain = (res) => /^http:/i.test(res?.url || '');

const CHECKS = {
  https(o) {
    const s = o.https;
    if (s.ok && isPlain(s)) return { status: 'fail', saw: `The secure address sends visitors back to plain http: ${clip(s.url, 120)}` };
    if (s.ok) {
      const moved = s.url && s.url !== `https://${o.host}/` ? ` at ${s.url}` : '';
      const tls = s.tls ? ` · ${s.tls.replace('TLSv', 'TLS ')}` : '';
      return { status: 'pass', saw: `Loads over HTTPS (status ${s.status})${moved}${tls}` };
    }
    return { status: 'fail', saw: `HTTPS failed: ${why(s.error)}.` };
  },

  redirect(o) {
    const p = o.http;
    if (!o.https.ok) return NO_SECURE;
    if (!p.ok) {
      if (p.error === 'ECONNREFUSED') return { status: 'pass', saw: 'Plain http is switched off completely.' };
      return { status: 'skip', saw: `Couldn't check plain http: ${why(p.error)}.` };
    }
    if (p.next) return { status: 'pass', saw: `http://${o.host}/ → ${p.chain.at(-1).status} → ${p.next}` };
    if (p.status >= 400) return { status: 'warn', saw: `http://${o.host}/ shows an error (${p.status}) instead of sending visitors to https.` };
    return { status: 'fail', saw: `http://${o.host}/ shows the site without switching to https (status ${p.status}).` };
  },

  cert(o, now) {
    const c = o.https.cert;
    if (!c && isPlain(o.https)) return { status: 'fail', saw: 'The final page is on plain http, so there is no certificate to read.' };
    if (!c) return { status: 'fail', saw: o.https.ok ? 'No certificate details came back.' : 'No working certificate.' };
    const days = Math.floor((Date.parse(c.validTo) - now) / 86400000);
    const by = c.issuer ? ` · issued by ${c.issuer}` : '';
    if (days < 0) return { status: 'fail', saw: `Expired ${fmtDate(c.validTo)}${by}`, days };
    const saw = `Expires ${fmtDate(c.validTo)} · ${plural(days, 'day')} left${by}`;
    if (CERT_CODES.has(o.https.error)) return { status: 'fail', saw: `${cap(why(o.https.error))}. ${saw}`, days };
    return { status: days < 7 ? 'fail' : days < 21 ? 'warn' : 'pass', saw, days };
  },

  hsts(o) {
    if (!o.https.headers) return NO_SECURE;
    const v = hdr(o.https, 'strict-transport-security');
    if (!v) return { status: 'warn', saw: 'Not set' };
    const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(v)?.[1] ?? NaN);
    if (!Number.isFinite(age) || age === 0) return { status: 'warn', saw: `${clip(v)} (switched off)` };
    if (age < 15552000) return { status: 'warn', saw: `${clip(v)} (${span(age)}; 180 days or more is the norm)` };
    return { status: 'pass', saw: clip(v) };
  },

  mixed(o, now, pg, page) {
    const s = o.https;
    if (!s.headers) return NO_SECURE;
    const type = hdr(s, 'content-type');
    if (!s.body || (type && !/html/i.test(type))) return { status: 'skip', saw: "The homepage didn't come back as a web page." };
    const { active, passive } = page;
    const files = [...active, ...passive], n = files.length;
    if (!n) return { status: 'pass', saw: 'No http:// files on the homepage.' };
    const list = files.slice(0, 3).join(', ') + (n > 3 ? ` and ${n - 3} more` : '');
    const policy = hdr(s, 'content-security-policy') + ';' + page.metaCsp;
    if (/upgrade-insecure-requests/i.test(policy)) return { status: 'pass', saw: `${plural(n, 'file')} over http://, but your security policy upgrades them: ${list}`, files };
    return { status: active.length ? 'fail' : 'warn', saw: `${plural(n, 'file')} over http://: ${list}`, files };
  },

  forms(o, now, pg, page) {
    if (!pg) return NO_PAGE;
    const n = page.forms.length;
    if (!n && !page.hasPassword) return { status: 'pass', saw: "No forms in the homepage's HTML." };
    if (isPlain(pg)) return { status: 'fail', saw: `${n > 1 ? plural(n, 'form') : 'A form'} on a page with no encryption, so what people type can be read along the way.` };
    const open = [...new Set(page.forms.map((f) => f.action).filter((a) => /^http:\/\//i.test(a)))];
    if (open.length) return { status: 'fail', saw: `${plural(open.length, 'form')} sending over plain http: ${open.slice(0, 2).map((a) => clip(a, 80)).join(', ')}`, files: open };
    return { status: 'pass', saw: `${plural(n, 'form')}, all sending over https.` };
  },

  www(o) {
    const w = o.www;
    if (!w?.applies) return { status: 'skip', saw: "Doesn't apply: this address has no separate www version." };
    if (w.ok && w.status < 400) return { status: 'pass', saw: `${w.host} works too.` };
    if (w.ok) return { status: 'warn', saw: `${w.host} shows an error page (status ${w.status}).` };
    if (CERT_CODES.has(w.error)) return { status: 'fail', saw: `${w.host} shows a security warning: ${why(w.error)}.` };
    if (w.error === 'ETIMEDOUT' || w.error === 'EAI_AGAIN') return { status: 'skip', saw: `Couldn't check ${w.host}: ${why(w.error)}.` };
    if (w.error === 'ENOTFOUND') return { status: 'warn', saw: `${w.host} doesn't exist, so people who type it hit a dead end.` };
    return { status: 'warn', saw: `${w.host} didn't load: ${why(w.error)}.` };
  },

  framing(o, now, pg) {
    if (!pg) return NO_PAGE;
    const fa = policies(hdr(pg, 'content-security-policy')).map((d) => d['frame-ancestors']).find((x) => x && !/(^|\s)\*(\s|$)/.test(x));
    if (fa) return { status: 'pass', saw: `Content-Security-Policy: frame-ancestors ${clip(fa, 80)}` };
    const xfo = hdr(pg, 'x-frame-options').trim();
    if (/^(deny|sameorigin)$/i.test(xfo)) return { status: 'pass', saw: `X-Frame-Options: ${xfo}` };
    if (xfo) return { status: 'warn', saw: `X-Frame-Options: ${clip(xfo, 60)} (browsers ignore this value)` };
    return { status: 'warn', saw: 'Not set' };
  },

  nosniff(o, now, pg) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'x-content-type-options').trim();
    if (/^nosniff$/i.test(v.split(',')[0].trim())) return { status: 'pass', saw: 'X-Content-Type-Options: nosniff' };
    return { status: 'warn', saw: v ? `X-Content-Type-Options: ${clip(v, 60)} (not a valid value)` : 'Not set' };
  },

  csp(o, now, pg, page) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'content-security-policy') || page.metaCsp;
    if (!v) return { status: 'warn', saw: hdr(pg, 'content-security-policy-report-only') ? 'Only in test mode (Report-Only), so nothing is blocked yet' : 'Not set' };
    const judged = policies(v).map((d) => d['script-src'] ?? d['default-src']).filter((src) => src !== undefined).map((src) => ({
      inline: /'unsafe-inline'/.test(src) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(src),
      anywhere: /(^|\s)(\*|https?:|data:)(\s|$)/.test(src),
    }));
    if (!judged.length) return { status: 'warn', saw: `${clip(v)} (doesn't limit scripts)` };
    if (judged.some((j) => !j.inline && !j.anywhere)) return { status: 'pass', saw: clip(v) };
    return { status: 'warn', saw: `${clip(v)} (still lets ${judged[0].inline ? 'inline' : 'any-site'} scripts run)` };
  },

  referrer(o, now, pg) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'referrer-policy');
    if (!v) return { status: 'pass', saw: 'Not set, so browsers use their safe default (strict-origin-when-cross-origin).' };
    const last = v.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean).at(-1);
    if (last === 'unsafe-url' || last === 'no-referrer-when-downgrade') return { status: 'warn', saw: `${clip(v, 80)} (shares full page addresses)` };
    return { status: 'pass', saw: clip(v, 80) };
  },

  permissions(o, now, pg) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'permissions-policy');
    if (v) return { status: 'pass', saw: clip(v) };
    if (hdr(pg, 'feature-policy')) return { status: 'warn', saw: 'Uses the old Feature-Policy name, which browsers no longer read' };
    return { status: 'warn', saw: 'Not set' };
  },

  cookies(o, now, pg) {
    if (!pg) return NO_PAGE;
    const list = [pg.headers['set-cookie'] ?? []].flat();
    if (!list.length) return { status: 'pass', saw: 'No cookies set on the homepage.' };
    const issues = cookieIssues(list, pg === o.https);
    if (!issues.length) return { status: 'pass', saw: `${plural(list.length, 'cookie')}, all properly flagged.` };
    const shown = issues.slice(0, 3).map((c) => `${clip(c.name, 40)}: missing ${c.miss.join(', ')}`).join('; ');
    return { status: 'warn', saw: shown + (issues.length > 3 ? `; and ${issues.length - 3} more` : ''), issues };
  },

  leaks(o, now, pg, page) {
    if (!pg) return NO_PAGE;
    const names = { server: 'Server', 'x-powered-by': 'X-Powered-By', 'x-aspnet-version': 'X-AspNet-Version', 'x-aspnetmvc-version': 'X-AspNetMvc-Version', 'x-generator': 'X-Generator' };
    const found = [];
    for (const [k, label] of Object.entries(names)) { const v = hdr(pg, k); if (/\d+\.\d+/.test(v)) found.push(`${label}: ${clip(v, 60)}`); }
    for (const gen of page.generators.filter((g) => /\d+\.\d+/.test(g)).slice(0, 2)) found.push(`page says it was made with ${clip(gen, 60)}`);
    return found.length ? { status: 'warn', saw: found.join(' · '), found } : { status: 'pass', saw: 'No software versions showing.' };
  },

  spf(o) {
    const d = o.dns, shared = sharedSuffix(o.domain);
    if (shared) return { status: 'skip', saw: `This site uses a shared ${shared} address, so its email records belong to the platform.` };
    if (!d.ok) return { status: 'skip', saw: "Couldn't read your domain's DNS records right now." };
    const mail = d.org ?? o.domain;
    if (!d.spf.length) return { status: 'fail', saw: `No SPF record on ${mail}.` };
    if (d.spf.length > 1) return { status: 'fail', saw: `${d.spf.length} SPF records. Inboxes treat that as having none at all.` };
    const r = d.spf[0];
    const where = d.spfAt && d.spfAt !== o.domain ? ` (set on ${d.spfAt})` : '';
    const all = /(?:^|\s)([-~?+]?)all(?:\s|$)/i.exec(r);
    if (!all && /(?:^|\s)redirect=/i.test(r)) return { status: 'pass', saw: clip(r) + where };
    if (!all) return { status: 'warn', saw: `${clip(r)}${where} (doesn't end with ~all or -all)` };
    const q = all[1] || '+';
    if (q === '+') return { status: 'fail', saw: `${clip(r)}${where} (+all lets any server send email as you)` };
    if (q === '?') return { status: 'warn', saw: `${clip(r)}${where} (?all doesn't tell inboxes to do anything)` };
    return { status: 'pass', saw: clip(r) + where };
  },

  dmarc(o) {
    const d = o.dns, shared = sharedSuffix(o.domain);
    if (shared) return { status: 'skip', saw: `This site uses a shared ${shared} address, so its email records belong to the platform.` };
    if (!d.ok) return { status: 'skip', saw: "Couldn't read your domain's DNS records right now." };
    if (!d.dmarc.length) return { status: 'fail', saw: `No DMARC record at _dmarc.${d.org ?? o.domain}.` };
    if (d.dmarc.length > 1) return { status: 'fail', saw: `${d.dmarc.length} DMARC records. Inboxes ignore all of them.` };
    const r = d.dmarc[0];
    const where = d.dmarcAt && d.dmarcAt !== o.domain ? ` (set on ${d.dmarcAt})` : '';
    const p = /(?:^|;)\s*p\s*=\s*(\w+)/i.exec(r)?.[1]?.toLowerCase();
    if (p === 'reject' || p === 'quarantine') return { status: 'pass', saw: clip(r) + where };
    if (p === 'none') return { status: 'warn', saw: `${clip(r)}${where} (watch-only: fake email still gets delivered)` };
    return { status: 'fail', saw: `${clip(r)}${where} (no valid p= policy, so inboxes ignore it)` };
  },

  dkim(o) {
    if (sharedSuffix(o.domain)) return { status: 'info', saw: `Shared ${sharedSuffix(o.domain)} address, so email signing belongs to the platform.` };
    if (!o.dns.ok || !o.dkim?.ok) return { status: 'info', saw: "Couldn't look this up right now." };
    if (o.dkim.found?.length) return { status: 'info', saw: `Found a signing key at ${o.dkim.found[0]}._domainkey.${o.dns.org ?? o.domain}.` };
    if (!o.dns.mx.length) return { status: 'info', saw: "This domain doesn't receive email, so there may be nothing to sign." };
    return { status: 'info', saw: "None at the usual names. That doesn't mean you have none, so it doesn't count against you." };
  },

  blocklist(o) {
    const r = o.rep ?? {};
    const say = (list) => list.join(' and ');
    const blocked = [r.cloudflare === 'blocked' && 'Cloudflare', r.quad9 === 'blocked' && 'Quad9'].filter(Boolean);
    if (blocked.length) return { status: 'fail', saw: `${say(blocked)}'s security ${blocked.length > 1 ? 'filters block' : 'filter blocks'} this address as dangerous.` };
    const clean = [r.cloudflare === 'clean' && 'Cloudflare', r.quad9 === 'clean' && 'Quad9'].filter(Boolean);
    if (!clean.length) return { status: 'skip', saw: "Couldn't reach the security filters right now." };
    return { status: 'pass', saw: `Not blocked by ${clean.join(' or ')}'s malware ${clean.length > 1 ? 'filters' : 'filter'}.` };
  },

  software(o, now, pg, page) {
    if (!pg) return NO_PAGE;
    const libs = libraries(page.scripts);
    const risky = libs.filter((l) => l.risky);
    const wp = o.wp;
    const lines = risky.map((l) => `${l.name} ${l.version} (${l.why})`);
    if (wp?.status === 'insecure') return { status: 'fail', saw: [`WordPress ${wp.version}: WordPress lists this version as insecure`, ...lines].join(' · '), risky };
    if (wp?.status === 'outdated') lines.unshift(`WordPress ${wp.version}: a newer release is out`);
    if (lines.length) return { status: 'warn', saw: lines.join(' · '), risky };
    const seen = [...(wp?.status === 'latest' ? [`WordPress ${wp.version}`] : []), ...libs.map((l) => `${l.name} ${l.version}`)];
    return { status: 'pass', saw: seen.length ? `Nothing risky: ${seen.slice(0, 4).join(', ')}.` : "No risky versions showing in the homepage's HTML." };
  },

  renewal(o, now) {
    if (sharedSuffix(o.domain)) return { status: 'skip', saw: `The platform owns ${sharedSuffix(o.domain)}, so renewing it is their job.` };
    const r = o.rdap;
    if (!r?.ok) return { status: 'skip', saw: "We couldn't reach the domain registry this time, so this wasn't checked." };
    if (!r.expires) return { status: 'skip', saw: "This domain's registry doesn't publish renewal dates." };
    const days = Math.floor((Date.parse(r.expires) - now) / DAY);
    const by = r.registrar ? ` · registrar: ${clip(r.registrar, 60)}` : '';
    if (days < 0) return { status: 'fail', saw: `Expired ${fmtDate(r.expires)}${by}`, days };
    const saw = `Paid through ${fmtDate(r.expires)} · ${plural(days, 'day')} left${by}`;
    return { status: days < 14 ? 'fail' : days < 30 ? 'warn' : 'pass', saw, days };
  },

  lock(o) {
    if (sharedSuffix(o.domain)) return { status: 'skip', saw: `The platform owns ${sharedSuffix(o.domain)}, so this one is theirs too.` };
    const r = o.rdap;
    if (!r?.ok) return { status: 'skip', saw: "We couldn't reach the domain registry this time, so this wasn't checked." };
    if (r.status.some((s) => /transfer\s*prohibited/.test(s))) return { status: 'pass', saw: 'The transfer lock is on.' };
    // many country domains don't use these status codes at all, so silence there proves nothing
    if (!r.status.length || (o.dns?.org ?? o.domain).split('.').at(-1).length === 2) return { status: 'skip', saw: "This domain's registry doesn't report transfer locks." };
    return { status: 'warn', saw: 'No transfer lock showing on the domain.' };
  },

  thirdparty(o, now, pg, page) {
    if (!pg) return { status: 'info', saw: "Couldn't load the homepage to check this." };
    const names = thirdParties(page, o.domain);
    if (!names.length) return { status: 'info', saw: "None in the homepage's HTML." };
    const shown = names.slice(0, 8).join(', ') + (names.length > 8 ? ` and ${names.length - 8} more` : '');
    return { status: 'info', saw: `${names.length} ${names.length === 1 ? 'company' : 'companies'}: ${shown}. Tag managers can load more than this list shows.` };
  },
};

/* ---------------- fixes ---------------- */

const HEADER_FIX = {
  hsts: ['Strict-Transport-Security', 'max-age=31536000'],
  framing: ['X-Frame-Options', 'SAMEORIGIN'],
  nosniff: ['X-Content-Type-Options', 'nosniff'],
  csp: ['Content-Security-Policy', "upgrade-insecure-requests; frame-ancestors 'self'"],
  referrer: ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  permissions: ['Permissions-Policy', 'camera=(), microphone=(), geolocation=()'],
};

export function headerSnippet(platform, pairs) {
  const xml = (s) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
  switch (platform) {
    case 'vercel':
      return { file: 'vercel.json', code: JSON.stringify({ headers: [{ source: '/(.*)', headers: pairs.map(([key, value]) => ({ key, value })) }] }, null, 2) };
    case 'netlify':
      return { file: '_headers (in your publish folder)', code: '/*\n' + pairs.map(([k, v]) => `  ${k}: ${v}`).join('\n') };
    case 'apache': case 'litespeed':
      return { file: '.htaccess', code: '<IfModule mod_headers.c>\n' + pairs.map(([k, v]) => `  Header always set ${k} "${v}"`).join('\n') + '\n</IfModule>' };
    case 'nginx':
      return { file: 'your nginx server { } block', code: pairs.map(([k, v]) => `add_header ${k} "${v}" always;`).join('\n') };
    case 'iis':
      return { file: 'web.config', code: '<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n' + pairs.map(([k, v]) => `      <add name="${k}" value="${xml(v)}" />`).join('\n') + '\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>' };
    case 'cloudflare':
      return { file: 'Cloudflare dashboard → Rules → Transform Rules → Modify Response Header', code: pairs.map(([k, v]) => `Set static   ${k}   ${v}`).join('\n') };
    default:
      return { file: 'ask your web host to add these response headers', code: pairs.map(([k, v]) => `${k}: ${v}`).join('\n') };
  }
}

function emailProvider(mx = []) {
  const all = mx.join(' ');
  if (/google\.com|googlemail\.com/.test(all)) return ['Google Workspace', 'v=spf1 include:_spf.google.com ~all'];
  if (/outlook\.com/.test(all)) return ['Microsoft 365', 'v=spf1 include:spf.protection.outlook.com -all'];
  if (/zoho\./.test(all)) return ['Zoho Mail', 'v=spf1 include:zoho.com ~all'];
  if (/protonmail\.ch/.test(all)) return ['Proton Mail', 'v=spf1 include:_spf.protonmail.ch ~all'];
  if (/secureserver\.net/.test(all)) return ['GoDaddy email', 'v=spf1 include:secureserver.net -all'];
  if (/privateemail\.com/.test(all)) return ['Namecheap Private Email', 'v=spf1 include:spf.privateemail.com ~all'];
  if (/messagingengine\.com/.test(all)) return ['Fastmail', 'v=spf1 include:spf.messagingengine.com ~all'];
  if (/icloud\.com/.test(all)) return ['iCloud Mail', 'v=spf1 include:icloud.com ~all'];
  return null;
}

/* One SPF record that keeps every sender from all of them. Dropping one would break that sender's real email. */
export function mergeSpf(records) {
  const terms = [];
  let strict = true;
  for (const r of records) {
    // a record with no `-all` of its own (a bare list, or a redirect to someone else's policy) never promised strict
    if (!/(^|\s)-all(\s|$)/i.test(r)) strict = false;
    for (const t of r.trim().split(/\s+/).slice(1)) {
      if (/^[-~?+]?all$/i.test(t)) continue;
      const term = t.replace(/^redirect=/i, 'include:');
      if (!terms.includes(term)) terms.push(term);
    }
  }
  return ['v=spf1', ...terms, strict ? '-all' : '~all'].join(' ');
}

const WEB_PERSON = 'your web person';
const REGISTRAR = 'you, at your domain registrar';

function buildFixes(checks, o, platform, builder, pg, page) {
  const by = Object.fromEntries(checks.map((c) => [c.id, c]));
  const bad = (id) => by[id] && (by[id].status === 'fail' || by[id].status === 'warn');
  const lost = (id) => (bad(id) ? by[id].weight * (1 - CREDIT[by[id].status]) : 0);
  const fixes = [];
  /* `unearned` lists checks this fix helps but won't flip to a pass, so it never promises points it can't deliver. */
  const add = (ids, { unearned = [], ...fix }) => {
    const ls = [ids].flat().filter(bad);
    if (ls.length) fixes.push({ ...fix, ids: ls, points: ls.filter((id) => !unearned.includes(id)).reduce((s, id) => s + lost(id), 0) });
  };
  const secure = by.https.status === 'pass';
  const mail = o.dns.org ?? o.domain;

  add('blocklist', {
    title: 'Get your site off the blocklist', urgent: true, who: WEB_PERSON, time: 'a few hours', mins: 240,
    text: "Have someone scan the site for malware and clean it first, because a hacked site is the usual reason for a listing. Then ask each filter to review it. If the site is clean and this is a mistake, the same forms fix that.",
    links: [{ label: 'Ask Cloudflare to review', href: 'https://radar.cloudflare.com/domains/feedback' }, { label: 'Ask Quad9 to review', href: 'https://quad9.net/support/contact/' }],
  });
  add(secure ? [] : ['https', 'cert', 'redirect'], {
    title: 'Turn on HTTPS', urgent: true, who: 'your web host', time: 'about 30 minutes', mins: 30,
    text: "Switch on HTTPS at your web host. Most hosts do it free with one setting (often called SSL or Let's Encrypt). If it's already on, the certificate may be for the wrong domain or out of date. Then make plain http forward to https.",
  });
  if (secure) add('cert', { title: 'Renew the certificate', who: 'your web host', time: 'about 15 minutes', mins: 15, text: "Renew it now and switch on automatic renewal at your host. Free Let's Encrypt certificates renew themselves when that's set up." });
  add('renewal', {
    title: by.renewal?.status === 'fail' ? 'Renew your domain now' : 'Check your domain renewal', urgent: by.renewal?.status === 'fail', who: REGISTRAR, time: 'about 5 minutes', mins: 5,
    text: `Log in${o.rdap?.registrar ? ` at ${clip(o.rdap.registrar, 60)}` : ' at your registrar'}, renew the domain and switch on auto-renew. Check that the card on file is still good, because a declined card is how most domains lapse by accident.`,
  });

  const redirectCode = {
    apache: { file: '.htaccess', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    litespeed: { file: '.htaccess', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    nginx: { file: 'your nginx config', code: 'server {\n  listen 80;\n  server_name ' + o.host + ';\n  return 301 https://$host$request_uri;\n}' },
  }[platform];
  if (secure) add('redirect', { title: 'Send http visitors to https', who: redirectCode ? WEB_PERSON : 'your web host', time: 'about 10 minutes', mins: 10, text: platform === 'cloudflare' ? 'In Cloudflare, open SSL/TLS → Edge Certificates and switch on Always Use HTTPS.' : redirectCode ? 'Add a permanent redirect from http to https:' : 'Look for a setting called "Force HTTPS" or "Always use HTTPS" at your host and switch it on.', ...redirectCode });

  if (bad('www')) {
    const warned = by.www.status === 'fail';
    add('www', {
      title: warned ? `Fix the security warning on ${o.www.host}` : `Make ${o.www.host} work`, who: 'your web host', time: 'about 15 minutes', mins: 15,
      text: warned ? `Your certificate doesn't cover ${o.www.host}. Add that name to the domains in your hosting settings so the certificate includes it, and forward it to your main address.`
        : `Add ${o.www.host} to the domains in your hosting settings and point it at your site with a DNS record at your registrar, so both spellings land in the same place.`,
    });
  }

  const pgCsp = pg ? hdr(pg, 'content-security-policy') || page.metaCsp : '';
  const weakPolicy = bad('csp') && !!pgCsp;
  const locked = LOCKED.has(platform) || LOCKED.has(builder);
  const headerIds = ['hsts', 'framing', 'csp', 'nosniff', 'permissions', 'referrer'].filter((id) => bad(id) && !(id === 'hsts' && !secure) && !(id === 'csp' && weakPolicy));
  if (headerIds.length) {
    if (!locked) {
      const pairs = headerIds.map((id) => HEADER_FIX[id]);
      const wp = builder === 'wordpress' && !['apache', 'litespeed', 'nginx', 'iis'].includes(platform) ? ' On WordPress, a security-headers plugin can add these too.' : '';
      const note = headerIds.includes('csp') ? " The Content-Security-Policy line is a safe starter that can't break your scripts. It won't raise your score by itself: a policy that limits scripts needs testing on your site first." : '';
      add(headerIds, { title: 'Add the missing security headers', unearned: ['csp'], who: WEB_PERSON, time: 'about 15 minutes', mins: 15, text: `Add ${pairs.length === 1 ? 'this header' : 'these headers'} to every page.${note}${wp}`, ...headerSnippet(platform, pairs) });
    }
  }
  if (locked) {
    const theirs = [...headerIds, 'cookies', 'leaks'].filter(bad);
    const name = BUILDERS[builder] ?? PLATFORMS[platform];
    add(theirs, { title: 'Security headers', unearned: theirs, who: `${name} support`, time: 'one support ticket', mins: 30, text: `${name} controls these settings and doesn't let you change them yourself. Ask their support about them, and spend your time on the fixes you do control.` });
  }
  if (weakPolicy && !locked) add('csp', { title: 'Tighten your Content Security Policy', who: WEB_PERSON, time: 'a few hours', mins: 240, text: "You have a policy, but it still lets some scripts through. Tightening it means listing where your scripts come from and removing 'unsafe-inline'. The wrong rule can break pages, so test it in Report-Only mode first." });

  if (secure && by.forms.files?.length) add('forms', { title: 'Send your forms over https', who: WEB_PERSON, time: 'about 15 minutes', mins: 15, text: "Change the form's address from http:// to https:// so what people type stays encrypted:", file: 'forms to fix', code: by.forms.files.slice(0, 10).join('\n') });
  if (by.mixed.files?.length) add('mixed', { title: 'Load every file over https', who: WEB_PERSON, time: 'about 30 minutes', mins: 30, text: "Change these addresses from http:// to https:// in your site's code or page builder:", file: 'insecure files', code: by.mixed.files.slice(0, 10).join('\n') });
  if (bad('cookies') && !locked) add('cookies', { title: 'Flag your cookies', who: WEB_PERSON, time: 'about 30 minutes', mins: 30, text: 'Ask whoever set up your site (or check your plugin settings) to add the missing flags. Secure, HttpOnly and SameSite=Lax suit most cookies.', file: 'cookies to fix', code: by.cookies.issues.map((c) => `${c.name}: add ${c.miss.join(', ')}`).join('\n') });

  if (bad('software')) {
    const wpOld = o.wp?.status === 'insecure' || o.wp?.status === 'outdated';
    const libs = by.software.risky ?? [];
    add('software', {
      title: wpOld ? 'Update WordPress' : 'Update your old code libraries', who: wpOld ? 'you or your web person' : WEB_PERSON, time: wpOld ? 'about 30 minutes' : 'about an hour', mins: wpOld ? 30 : 60,
      text: wpOld ? 'Back up the site, then open Dashboard → Updates and update WordPress, your plugins and your theme. Turn on automatic updates so this stays fixed.'
        : 'Ask your web person to update these and test the pages that use them, since old plugins can depend on old versions:',
      ...(libs.length ? { file: 'versions to update', code: libs.map((l) => `${l.name} ${l.version} → ${/^\d/.test(l.fix) ? `${l.fix} or newer` : l.fix}`).join('\n') } : {}),
    });
  }

  if (bad('leaks') && !locked) {
    const lines = {
      apache: 'ServerTokens Prod\nServerSignature Off\n# and in php.ini:\nexpose_php = Off',
      litespeed: 'ServerTokens Prod\n# and in php.ini:\nexpose_php = Off',
      nginx: 'server_tokens off;\n# and in php.ini, if you use PHP:\nexpose_php = Off',
    }[platform];
    const found = by.leaks.found || [];
    const wp = found.some((f) => /wordpress/i.test(f));
    const inPage = found.some((f) => f.startsWith('page says'));
    const inHeaders = found.some((f) => !f.startsWith('page says'));
    const pageText = builder === 'wordpress' ? 'A plugin or theme is printing its version into your page. A security plugin can remove these tags. Then keep your plugins updated.' : "Your site's software is printing its version into the page. Look for a setting that hides it, and keep that software updated.";
    add('leaks', {
      title: 'Hide version numbers (and keep that software updated)', who: WEB_PERSON, time: 'about 15 minutes', mins: 15,
      text: wp ? 'Remove the WordPress version tag with a security plugin, or add this to your theme\'s functions.php. Then keep WordPress and its plugins updated.'
        : inHeaders && lines ? `Switch off the version banners in your server settings:${inPage ? ' Your page also prints a version: a plugin or theme setting usually hides that.' : ''}`
        : inHeaders ? 'Ask your host to stop sending version numbers in the Server and X-Powered-By headers.' : pageText,
      ...(wp ? { file: 'functions.php', code: "remove_action('wp_head', 'wp_generator');" } : inHeaders && lines ? { file: 'server config', code: lines } : {}),
    });
  }

  const noMail = o.dns.ok && !o.dns.mx.length;
  if (bad('spf')) {
    const prov = emailProvider(o.dns.mx);
    const multiple = o.dns.spf.length > 1;
    const value = multiple ? mergeSpf(o.dns.spf) : noMail ? 'v=spf1 -all' : prov ? prov[1] : 'v=spf1 include:(your email provider\'s SPF domain) ~all';
    add('spf', {
      title: multiple ? 'Merge your SPF records into one' : 'Add an SPF record', who: REGISTRAR, time: 'about 5 minutes', mins: 5,
      text: noMail && !multiple ? "Your domain doesn't receive email, so tell inboxes that nothing sends email as you. Add this TXT record at your domain registrar:"
        : multiple ? 'Inboxes ignore SPF when there is more than one record. Replace them all with this one TXT record, which keeps every sender from both:'
        : prov ? `Your email is handled by ${prov[0]}. Add this TXT record at your domain registrar:` : "Add a TXT record at your domain registrar. Your email provider's setup guide lists the exact include: value.",
      file: `TXT record · name: @ (${mail})`, code: value,
    });
  }
  if (bad('dmarc')) {
    const none = by.dmarc.status === 'warn';
    add('dmarc', {
      title: none ? 'Switch DMARC from watch-only to protect' : 'Add a DMARC record', who: REGISTRAR, time: 'about 5 minutes', mins: 5,
      text: noMail ? "Your domain doesn't receive email, so tell inboxes to reject anything that claims to be from you:"
        : none ? 'Once your real email passes SPF, change p=none to p=quarantine so fake email goes to junk:'
        : 'Add this TXT record. It sends fake email that uses your domain to junk. If you send a lot of email, start with p=none for two weeks, then switch to quarantine.',
      file: `TXT record · name: _dmarc (_dmarc.${mail})`, code: noMail ? 'v=DMARC1; p=reject' : 'v=DMARC1; p=quarantine',
    });
  }
  add('lock', { title: 'Lock your domain', who: REGISTRAR, time: 'about 2 minutes', mins: 2, text: 'In your registrar\'s settings, look for "transfer lock", "registrar lock" or "domain lock" and switch it on. It\'s free, and you can turn it off if you ever move the domain yourself.' });

  const rank = (f) => f.points + (f.urgent ? 1000 : 0);
  return fixes.sort((a, b) => rank(b) - rank(a));
}

/* ---------------- grade ---------------- */

export function gradeOf(score) {
  return score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';
}

/* A plain-English reason to stop before grading, or null when there's a site to grade. */
export function unreachable(o) {
  const codes = [o.https.error, o.http.error];
  if (codes.includes('EBLOCKED')) return "That address points to a private network, so it can't be checked.";
  if (o.https.ok || o.https.headers || (o.http.ok && o.http.status)) return null;
  if (codes.every((c) => c === 'ENOTFOUND')) return "We couldn't find a website at that address. Check the spelling.";
  return "That website didn't answer. It may be down, or it may be blocking checks like this one.";
}

export function evaluate(o, { now = Date.now() } = {}) {
  const pg = pageOf(o);
  const page = parsePage(pg?.body);
  const checks = GROUPS.flatMap(([group, , ids]) => ids.map((id) => {
    const r = CHECKS[id](o, now, pg, page);
    return { id, group, title: INFO[id][0], why: INFO[id][1], weight: WEIGHTS[id] ?? 0, ...r };
  }));
  const scored = checks.filter((c) => c.status in CREDIT);
  const total = scored.reduce((s, c) => s + c.weight, 0);
  const got = scored.reduce((s, c) => s + c.weight * CREDIT[c.status], 0);
  const score = total ? Math.round((got / total) * 100) : 0;
  const by = Object.fromEntries(checks.map((c) => [c.id, c]));
  const insecure = by.https.status === 'fail' || (by.cert.days ?? 0) < 0;
  const flagged = by.blocklist.status === 'fail';
  const capped = insecure || flagged;
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0, info: 0 };
  for (const c of checks) counts[c.status]++;
  const platform = detectPlatform(pg?.headers);
  const builder = detectBuilder(page);

  const notes = [];
  if (flagged) notes.push('The grade is capped at F because security filters list this site as dangerous. Fix that first: customers behind those filters can\'t reach you at all.');
  if (insecure) notes.push("The grade is capped at F because the secure connection doesn't work. Fix that first: everything else depends on it.");
  let caveat = null;
  if (pg && (hdr(pg, 'cf-mitigated') === 'challenge' || ([403, 503].includes(pg.status) && /challenge-platform|captcha/i.test(pg.body || '')))) {
    caveat = "Your site's firewall showed us a challenge page instead of your homepage, so this grade is rough. Your real page may do better or worse.";
  } else if (pg && [401, 403, 429].includes(pg.status)) {
    caveat = `Your site turned us away (status ${pg.status}), so we graded the page it sent instead of your homepage. Treat this grade as rough, and try Check again in a minute.`;
  } else if (pg && pg.status >= 400) {
    caveat = `Your homepage returned an error (status ${pg.status}) when we visited, so this grade may describe the error page rather than your site. If it's broken for us, it may be broken for your customers too.`;
  }
  const shared = sharedSuffix(o.domain);
  if (shared) notes.push(`Your site is on a shared ${shared} address. A domain of your own looks more trustworthy, and it lets you protect your email from spoofing.`);
  if (counts.skip) notes.push(`${counts.skip === 1 ? "1 check didn't" : `${counts.skip} checks didn't`} apply or couldn't run, so ${counts.skip === 1 ? "it doesn't count" : "they don't count"} toward the score.`);

  const scale = total ? 100 / total : 0;
  const raw = buildFixes(checks, o, platform, builder, pg, page);
  const gain = raw.reduce((s, f) => s + f.points, 0);
  const after = Math.min(100, Math.round((got + gain) * scale));
  const fixes = raw.map(({ ids, points, urgent, ...f }) => ({ ...f, checks: ids, points: Math.round(points * scale) }));
  const grade = capped ? 'F' : gradeOf(score);
  const potential = after > score ? { score: after, grade: gradeOf(after) } : null;
  const emailOpen = !shared && o.dns.ok && (by.dmarc.status === 'fail' || by.dmarc.status === 'warn' || by.spf.status === 'fail');

  // drop internal-only fields before the report leaves the server
  const clean = checks.map(({ files, issues, found, days, risky, ...c }) => c);
  return {
    host: o.host, domain: o.domain, finalUrl: o.https.url || null, fetchedAt: o.fetchedAt,
    platform: { id: platform, name: PLATFORMS[platform] },
    builder: builder ? { id: builder, name: BUILDERS[builder] } : null,
    registrar: o.rdap?.registrar ?? null,
    dates: { cert: o.https.cert?.validTo ?? null, certIssuer: o.https.cert?.issuer ?? null, domain: shared ? null : o.rdap?.expires ?? null },
    spoof: emailOpen ? { domain: o.dns.org ?? o.domain } : null,
    grade, score, capped, counts, potential, caveat,
    summary: summarize({ grade, checks: clean, fixes, potential }),
    checks: clean,
    fixes: fixes.map(({ mins, ...f }) => f),
    notes,
  };
}
