/* Turns raw observations (from inspect.js) into the graded report. Pure, no network, so the tests
   can feed it any site they like. Weights add up to 100: a pass earns the full weight, a warning
   half, a fail nothing. Checks that couldn't run ("skip") leave the total instead of costing points. */

export const WEIGHTS = { https: 18, redirect: 8, cert: 10, hsts: 8, mixed: 6, framing: 6, nosniff: 4, csp: 6, referrer: 2, permissions: 2, cookies: 6, leaks: 4, spf: 9, dmarc: 11 };
const CREDIT = { pass: 1, warn: 0.5, fail: 0 };

export const GROUPS = [
  ['connection', 'Connection', ['https', 'redirect', 'cert', 'hsts', 'mixed']],
  ['browser', 'Browser protections', ['framing', 'nosniff', 'csp', 'referrer', 'permissions', 'cookies', 'leaks']],
  ['email', 'Email', ['spf', 'dmarc']],
];

export const INFO = {
  https: ['Secure connection (HTTPS)', 'Without it, anyone on the same Wi-Fi can read or change what your customers see and type.'],
  redirect: ['Sends visitors to the secure version', 'People who type your address without https:// should still land on the secure site.'],
  cert: ['Security certificate is current', 'When it expires, browsers show a full-page warning and most visitors leave.'],
  hsts: ['Browsers remember to use HTTPS (HSTS)', 'Stops a trick on public Wi-Fi that keeps visitors on the insecure version of your site.'],
  mixed: ['No insecure files on the secure page', 'Scripts or images loaded over plain http can be swapped by an attacker, and browsers block some of them.'],
  framing: ["Can't be hidden inside another site", 'Stops scam pages from loading your site invisibly and tricking people into clicking your buttons.'],
  nosniff: ["Files can't pretend to be scripts (nosniff)", 'Stops browsers from running a file as code when it claims to be something else.'],
  csp: ['Content Security Policy', "A list of where your site's scripts may come from. If bad code sneaks in, the browser refuses to run it."],
  referrer: ['Page addresses stay private (Referrer-Policy)', 'Controls how much of your page address is shared when a visitor clicks a link to another site.'],
  permissions: ['Camera, mic and location locked (Permissions-Policy)', 'Makes sure nothing embedded in your site can ask visitors for their camera, microphone or location.'],
  cookies: ['Cookies are protected', 'Cookies can hold logins and carts. The Secure, HttpOnly and SameSite flags keep them from being stolen.'],
  leaks: ["Doesn't advertise software versions", "Showing exact versions (like 'Apache 2.4.41') tells attackers which known holes to try."],
  spf: ['Email sender list (SPF)', 'Tells inboxes which servers may send email as your domain. Without it, scammers can send fake invoices that look like yours.'],
  dmarc: ['Email spoofing protection (DMARC)', 'Tells inboxes what to do with fake email that uses your domain: let it in, send it to junk, or reject it.'],
};

export const PLATFORMS = {
  vercel: 'Vercel', netlify: 'Netlify', cloudflare: 'Cloudflare', shopify: 'Shopify', wix: 'Wix', squarespace: 'Squarespace',
  godaddy: 'GoDaddy Website Builder', 'github-pages': 'GitHub Pages', apache: 'Apache', litespeed: 'LiteSpeed', nginx: 'Nginx',
  iis: 'Microsoft IIS', unknown: 'Not detected',
};
// free shared addresses: the platform owns the domain, so its email records aren't the site owner's to fix
const SHARED = ['vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'onrender.com',
  'fly.dev', 'wixsite.com', 'squarespace.com', 'myshopify.com', 'webflow.io', 'framer.website', 'framer.app', 'carrd.co', 'godaddysites.com',
  'wordpress.com', 'blogspot.com', 'glitch.me', 'replit.app', 'surge.sh', 'azurewebsites.net', 'amplifyapp.com', 'up.railway.app', 'lovable.app'];
export const sharedSuffix = (domain) => SHARED.find((s) => domain === s || domain.endsWith('.' + s)) ?? null;
// hosted builders that don't let owners add their own response headers
const LOCKED = new Set(['shopify', 'wix', 'squarespace', 'godaddy', 'github-pages']);

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
};
const CERT_CODES = new Set(Object.keys(NET).filter((k) => /CERT|SIGN/.test(k)));
const why = (code) => NET[code] || 'the connection failed';
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const clip = (s, n = 160) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
const span = (secs) => (secs < 86400 ? plural(Math.max(1, Math.round(secs / 3600)), 'hour') : plural(Math.round(secs / 86400), 'day'));
const fmtDate = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });

// header value, with repeated headers (arrays) joined
function hdr(res, name) {
  const v = res?.headers?.[name];
  return Array.isArray(v) ? v.join(', ') : v ?? '';
}

// the page whose headers get judged: the secure one, or the plain-http page on an http-only site
function pageOf(o) {
  if (o.https.headers) return o.https;
  if (o.http.ok && !o.http.next && o.http.status < 400) return o.http;
  return null;
}

function metaCsp(html = '') {
  const tag = /<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/i.exec(html)?.[0];
  return tag ? /content\s*=\s*"([^"]*)"|content\s*=\s*'([^']*)'/i.exec(tag)?.slice(1).find(Boolean) ?? '' : '';
}

function directives(policy) {
  const out = {};
  for (const part of policy.split(';')) {
    const [name, ...rest] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in out)) out[name.toLowerCase()] = rest.join(' ');
  }
  return out;
}

/* <script>, <iframe>, stylesheets and plugins loaded over http get blocked ("active");
   images and media get upgraded or warned about ("passive"). */
export function insecureFiles(html = '') {
  const active = new Set(), passive = new Set();
  for (const m of html.matchAll(/<(script|img|iframe|source|video|audio|embed|link)\b[^>]*>/gi)) {
    const tag = m[1].toLowerCase(), raw = m[0];
    if (tag === 'link' && !/\brel\s*=\s*["']?[^"'>]*stylesheet/i.test(raw)) continue;
    const url = /\s(?:src|href|data)\s*=\s*["']?\s*(http:\/\/[^"'\s>]+)/i.exec(raw)?.[1];
    if (url) (['script', 'iframe', 'link', 'embed'].includes(tag) ? active : passive).add(url);
  }
  return { active: [...active], passive: [...passive] };
}

export function generator(html = '') {
  const tag = /<meta\b[^>]*name\s*=\s*["']?generator["']?[^>]*>/i.exec(html)?.[0];
  return tag ? /content\s*=\s*"([^"]*)"|content\s*=\s*'([^']*)'/i.exec(tag)?.slice(1).find(Boolean) ?? '' : '';
}

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
  return 'unknown';
}

/* ---------------- the fourteen checks ---------------- */

const NO_SECURE = { status: 'fail', saw: 'There is no working secure version of the site.' };
const NO_PAGE = { status: 'skip', saw: "Couldn't load the homepage to check this." };

const CHECKS = {
  https(o) {
    const s = o.https;
    if (s.ok) {
      const moved = s.url && s.url !== `https://${o.host}/` ? ` at ${s.url}` : '';
      return { status: 'pass', saw: `Loads over HTTPS (status ${s.status})${moved}` };
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

  mixed(o) {
    const s = o.https;
    if (!s.headers) return NO_SECURE;
    const type = hdr(s, 'content-type');
    if (!s.body || (type && !/html/i.test(type))) return { status: 'skip', saw: "The homepage didn't come back as a web page." };
    const { active, passive } = insecureFiles(s.body);
    const files = [...active, ...passive], n = files.length;
    if (!n) return { status: 'pass', saw: 'No http:// files on the homepage.' };
    const list = files.slice(0, 3).join(', ') + (n > 3 ? ` and ${n - 3} more` : '');
    const policy = hdr(s, 'content-security-policy') + ';' + metaCsp(s.body);
    if (/upgrade-insecure-requests/i.test(policy)) return { status: 'pass', saw: `${plural(n, 'file')} over http://, but your security policy upgrades them: ${list}`, files };
    return { status: active.length ? 'fail' : 'warn', saw: `${plural(n, 'file')} over http://: ${list}`, files };
  },

  framing(o, now, pg) {
    if (!pg) return NO_PAGE;
    const fa = directives(hdr(pg, 'content-security-policy'))['frame-ancestors'];
    if (fa && !/(^|\s)\*(\s|$)/.test(fa)) return { status: 'pass', saw: `Content-Security-Policy: frame-ancestors ${clip(fa, 80)}` };
    const xfo = hdr(pg, 'x-frame-options').trim();
    if (/^(deny|sameorigin)$/i.test(xfo)) return { status: 'pass', saw: `X-Frame-Options: ${xfo}` };
    if (xfo) return { status: 'warn', saw: `X-Frame-Options: ${clip(xfo, 60)} (browsers ignore this value)` };
    return { status: 'warn', saw: 'Not set' };
  },

  nosniff(o, now, pg) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'x-content-type-options').trim();
    if (/^nosniff$/i.test(v)) return { status: 'pass', saw: 'X-Content-Type-Options: nosniff' };
    return { status: 'warn', saw: v ? `X-Content-Type-Options: ${clip(v, 60)} (not a valid value)` : 'Not set' };
  },

  csp(o, now, pg) {
    if (!pg) return NO_PAGE;
    const v = hdr(pg, 'content-security-policy') || metaCsp(pg.body);
    if (!v) return { status: 'warn', saw: hdr(pg, 'content-security-policy-report-only') ? 'Only in test mode (Report-Only), so nothing is blocked yet' : 'Not set' };
    const d = directives(v);
    const src = d['script-src'] ?? d['default-src'];
    if (src === undefined) return { status: 'warn', saw: `${clip(v)} (doesn't limit scripts)` };
    const inline = /'unsafe-inline'/.test(src) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(src);
    const anywhere = /(^|\s)(\*|https?:|data:)(\s|$)/.test(src);
    if (inline || anywhere) return { status: 'warn', saw: `${clip(v)} (still lets ${inline ? 'inline' : 'any-site'} scripts run)` };
    return { status: 'pass', saw: clip(v) };
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

  leaks(o, now, pg) {
    if (!pg) return NO_PAGE;
    const names = { server: 'Server', 'x-powered-by': 'X-Powered-By', 'x-aspnet-version': 'X-AspNet-Version', 'x-aspnetmvc-version': 'X-AspNetMvc-Version', 'x-generator': 'X-Generator' };
    const found = [];
    for (const [k, label] of Object.entries(names)) { const v = hdr(pg, k); if (/\d+\.\d+/.test(v)) found.push(`${label}: ${clip(v, 60)}`); }
    const gen = generator(pg.body);
    if (/\d+\.\d+/.test(gen)) found.push(`page says it was made with ${clip(gen, 60)}`);
    return found.length ? { status: 'warn', saw: found.join(' · '), found } : { status: 'pass', saw: 'No software versions showing.' };
  },

  spf(o) {
    const d = o.dns, shared = sharedSuffix(o.domain);
    if (shared) return { status: 'skip', saw: `This site uses a shared ${shared} address, so its email records belong to the platform.` };
    if (!d.ok) return { status: 'skip', saw: "Couldn't read your domain's DNS records right now." };
    if (!d.spf.length) return { status: 'fail', saw: `No SPF record on ${o.domain}.` };
    if (d.spf.length > 1) return { status: 'fail', saw: `${d.spf.length} SPF records. Inboxes treat that as having none at all.` };
    const r = d.spf[0];
    const all = /(?:^|\s)([-~?+]?)all(?:\s|$)/i.exec(r);
    if (!all && /(?:^|\s)redirect=/i.test(r)) return { status: 'pass', saw: clip(r) };
    if (!all) return { status: 'warn', saw: `${clip(r)} (doesn't end with ~all or -all)` };
    const q = all[1] || '+';
    if (q === '+') return { status: 'fail', saw: `${clip(r)} (+all lets any server send email as you)` };
    if (q === '?') return { status: 'warn', saw: `${clip(r)} (?all doesn't tell inboxes to do anything)` };
    return { status: 'pass', saw: clip(r) };
  },

  dmarc(o) {
    const d = o.dns, shared = sharedSuffix(o.domain);
    if (shared) return { status: 'skip', saw: `This site uses a shared ${shared} address, so its email records belong to the platform.` };
    if (!d.ok) return { status: 'skip', saw: "Couldn't read your domain's DNS records right now." };
    if (!d.dmarc.length) return { status: 'fail', saw: `No DMARC record at _dmarc.${o.domain}.` };
    if (d.dmarc.length > 1) return { status: 'fail', saw: `${d.dmarc.length} DMARC records. Inboxes ignore all of them.` };
    const r = d.dmarc[0];
    const where = d.dmarcAt && d.dmarcAt !== o.domain ? ` (set on ${d.dmarcAt})` : '';
    const p = /(?:^|;)\s*p\s*=\s*(\w+)/i.exec(r)?.[1]?.toLowerCase();
    if (p === 'reject' || p === 'quarantine') return { status: 'pass', saw: clip(r) + where };
    if (p === 'none') return { status: 'warn', saw: `${clip(r)}${where} (watch-only: fake email still gets delivered)` };
    return { status: 'fail', saw: `${clip(r)}${where} (no valid p= policy, so inboxes ignore it)` };
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
  return null;
}

function buildFixes(checks, o, platform) {
  const by = Object.fromEntries(checks.map((c) => [c.id, c]));
  const bad = (id) => by[id] && (by[id].status === 'fail' || by[id].status === 'warn');
  const lost = (id) => (bad(id) ? by[id].weight * (1 - CREDIT[by[id].status]) : 0);
  const fixes = [];
  const add = (ids, fix) => { const ls = [ids].flat().filter(bad); if (ls.length) fixes.push({ ...fix, ids: ls, points: ls.reduce((s, id) => s + lost(id), 0) }); };

  add('https', { title: 'Turn on HTTPS', text: "Switch on HTTPS at your web host. Most hosts do it free with one setting (often called SSL or Let's Encrypt). If it's already on, the certificate may be for the wrong domain or out of date." });
  if (by.https.status === 'pass') add('cert', { title: 'Renew the certificate', text: "Renew it now and switch on automatic renewal at your host. Free Let's Encrypt certificates renew themselves when that's set up." });

  const redirectCode = {
    apache: { file: '.htaccess', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    litespeed: { file: '.htaccess', code: 'RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]' },
    nginx: { file: 'your nginx config', code: 'server {\n  listen 80;\n  server_name ' + o.host + ';\n  return 301 https://$host$request_uri;\n}' },
  }[platform];
  if (by.https.status === 'pass') add('redirect', { title: 'Send http visitors to https', text: platform === 'cloudflare' ? 'In Cloudflare, open SSL/TLS → Edge Certificates and switch on Always Use HTTPS.' : redirectCode ? 'Add a permanent redirect from http to https:' : 'Look for a setting called "Force HTTPS" or "Always use HTTPS" at your host and switch it on.', ...redirectCode });

  const headerIds = ['hsts', 'framing', 'csp', 'nosniff', 'permissions', 'referrer'].filter((id) => bad(id) && !(id === 'hsts' && by.https.status !== 'pass'));
  if (headerIds.length) {
    if (LOCKED.has(platform)) {
      add(headerIds, { title: 'Security headers', text: `${PLATFORMS[platform]} controls these headers and doesn't let you add your own. Ask their support about them, and spend your time on the email records below, which you do control.` });
    } else {
      const pairs = headerIds.map((id) => HEADER_FIX[id]);
      const note = headerIds.includes('csp') ? ' The Content-Security-Policy line is a safe starter that can\'t break your scripts; a stricter one needs testing on your site first.' : '';
      add(headerIds, { title: 'Add the missing security headers', text: `Add ${pairs.length === 1 ? 'this header' : 'these headers'} to every page.${note}`, ...headerSnippet(platform, pairs) });
    }
  }

  if (by.mixed.files?.length) add('mixed', { title: 'Load every file over https', text: "Change these addresses from http:// to https:// in your site's code or page builder:", file: 'insecure files', code: by.mixed.files.slice(0, 10).join('\n') });
  if (bad('cookies')) add('cookies', { title: 'Flag your cookies', text: 'Ask whoever set up your site (or check your plugin settings) to add the missing flags. Secure, HttpOnly and SameSite=Lax suit most cookies.', file: 'cookies to fix', code: by.cookies.issues.map((c) => `${c.name}: add ${c.miss.join(', ')}`).join('\n') });

  if (bad('leaks')) {
    const lines = {
      apache: 'ServerTokens Prod\nServerSignature Off\n# and in php.ini:\nexpose_php = Off',
      litespeed: 'ServerTokens Prod\n# and in php.ini:\nexpose_php = Off',
      nginx: 'server_tokens off;\n# and in php.ini, if you use PHP:\nexpose_php = Off',
    }[platform];
    const wp = (by.leaks.found || []).some((f) => /wordpress/i.test(f));
    add('leaks', {
      title: 'Hide version numbers (and keep that software updated)',
      text: wp ? 'Remove the WordPress version tag with a security plugin, or add this to your theme\'s functions.php. Then keep WordPress and its plugins updated.' : lines ? 'Switch off the version banners in your server settings:' : 'Ask your host to stop sending version numbers in the Server and X-Powered-By headers.',
      ...(wp ? { file: 'functions.php', code: "remove_action('wp_head', 'wp_generator');" } : lines ? { file: 'server config', code: lines } : {}),
    });
  }

  const noMail = o.dns.ok && !o.dns.mx.length;
  if (bad('spf')) {
    const prov = emailProvider(o.dns.mx);
    const value = noMail ? 'v=spf1 -all' : prov ? prov[1] : 'v=spf1 include:(your email provider\'s SPF domain) ~all';
    const multiple = o.dns.spf.length > 1;
    add('spf', {
      title: multiple ? 'Merge your SPF records into one' : 'Add an SPF record',
      text: noMail ? "Your domain doesn't receive email, so tell inboxes that nothing sends email as you. Add this TXT record at your domain registrar:"
        : multiple ? 'Inboxes ignore SPF when there is more than one record. Combine the include: parts into a single TXT record like this one:'
        : prov ? `Your email is handled by ${prov[0]}. Add this TXT record at your domain registrar:` : "Add a TXT record at your domain registrar. Your email provider's setup guide lists the exact include: value.",
      file: `TXT record · name: @ (${o.domain})`, code: value,
    });
  }
  if (bad('dmarc')) {
    const none = by.dmarc.status === 'warn';
    add('dmarc', {
      title: none ? 'Switch DMARC from watch-only to protect' : 'Add a DMARC record',
      text: noMail ? "Your domain doesn't receive email, so tell inboxes to reject anything that claims to be from you:"
        : none ? 'Once your real email passes SPF, change p=none to p=quarantine so fake email goes to junk:'
        : 'Add this TXT record. It sends fake email that uses your domain to junk. If you send a lot of email, start with p=none for two weeks, then switch to quarantine.',
      file: `TXT record · name: _dmarc (_dmarc.${o.domain})`, code: noMail ? 'v=DMARC1; p=reject' : 'v=DMARC1; p=quarantine',
    });
  }
  return fixes.sort((a, b) => b.points - a.points);
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
  const checks = GROUPS.flatMap(([group, , ids]) => ids.map((id) => {
    const r = CHECKS[id](o, now, pg);
    return { id, group, title: INFO[id][0], why: INFO[id][1], weight: WEIGHTS[id], ...r };
  }));
  const scored = checks.filter((c) => c.status !== 'skip');
  const total = scored.reduce((s, c) => s + c.weight, 0);
  const got = scored.reduce((s, c) => s + c.weight * CREDIT[c.status], 0);
  const score = total ? Math.round((got / total) * 100) : 0;
  const https = checks.find((c) => c.id === 'https'), cert = checks.find((c) => c.id === 'cert');
  const capped = https.status === 'fail' || (cert.days ?? 0) < 0;
  const counts = { pass: 0, warn: 0, fail: 0, skip: 0 };
  for (const c of checks) counts[c.status]++;
  const platform = detectPlatform(pg?.headers);

  const notes = [];
  if (capped) notes.push("The grade is capped at F because the secure connection doesn't work. Fix that first: everything else depends on it.");
  if (pg && (hdr(pg, 'cf-mitigated') === 'challenge' || ([403, 503].includes(pg.status) && /challenge-platform|captcha/i.test(pg.body || '')))) {
    notes.push("Your site's firewall showed DARE CHECK a challenge page, so some results may describe that page rather than your homepage.");
  } else if (pg && pg.status >= 500) {
    notes.push(`Your homepage returned an error (status ${pg.status}) when we visited, so some results may describe the error page.`);
  }
  const shared = sharedSuffix(o.domain);
  if (shared) notes.push(`Your site is on a shared ${shared} address. A domain of your own looks more trustworthy, and it lets you protect your email from spoofing.`);
  if (counts.skip) notes.push(`${plural(counts.skip, 'check')} couldn't run and didn't count toward the score.`);

  // drop internal-only fields before the report leaves the server
  const clean = checks.map(({ files, issues, found, days, ...c }) => c);
  return {
    host: o.host, domain: o.domain, finalUrl: o.https.url || null, fetchedAt: o.fetchedAt,
    platform: { id: platform, name: PLATFORMS[platform] },
    grade: capped ? 'F' : gradeOf(score), score, capped, counts,
    checks: clean, fixes: buildFixes(checks, o, platform).map(({ ids, points, ...f }) => ({ ...f, checks: ids, points: Math.round(points) })), notes,
  };
}
