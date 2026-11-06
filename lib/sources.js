/* Public lookups that never touch the scanned site: the domain registry's record (RDAP), two free
   security DNS filters, and WordPress's own list of insecure releases. None needs an API key.
   Each one fails soft: if a service is down, its check is skipped rather than guessed. */
import http2 from 'node:http2';
import { fetchChain } from './http.js';

const AGENT = 'DARE-CHECK/1.0 (+https://github.com/Waleee7/dare-check)';

export async function fetchJson(url, { accept = 'application/json', deadline = Date.now() + 5000 } = {}) {
  const r = await fetchChain(url, { deadline, maxBytes: 524288, headers: { 'user-agent': AGENT, accept } });
  let data = null;
  try { data = JSON.parse(r.body); } catch { /* the status still says what happened */ }
  return { status: r.status, data };
}

/* ---------------- domain registration ---------------- */

// the three biggest registries answer directly; rdap.org forwards everything else to the right one
const RDAP_DIRECT = {
  com: 'https://rdap.verisign.com/com/v1/domain/',
  net: 'https://rdap.verisign.com/net/v1/domain/',
  org: 'https://rdap.publicinterestregistry.org/rdap/domain/',
};

export function parseRdap(d = {}) {
  const when = (action) => {
    const v = d.events?.find?.((e) => e?.eventAction === action)?.eventDate;
    return v && Number.isFinite(Date.parse(v)) ? new Date(v).toISOString() : null;
  };
  const vcard = d.entities?.find?.((e) => e?.roles?.includes?.('registrar'))?.vcardArray?.[1];
  const name = vcard?.find?.((v) => v?.[0] === 'fn')?.[3];
  return {
    ok: true, expires: when('expiration'), created: when('registration'),
    registrar: typeof name === 'string' ? name.slice(0, 80) : null,
    status: Array.isArray(d.status) ? d.status.map((s) => String(s).toLowerCase()) : [],
  };
}

export async function domainRecord(domain, { json = fetchJson, deadline } = {}) {
  const top = domain.split('.').at(-1);
  const ask = async () => {
    try {
      const r = await json((RDAP_DIRECT[top] ?? 'https://rdap.org/domain/') + encodeURIComponent(domain), { accept: 'application/rdap+json', deadline });
      return r.status === 200 && r.data ? parseRdap(r.data) : { ok: false, error: `HTTP ${r.status}`, temporary: r.status === 429 || r.status >= 500 };
    } catch (e) {
      return { ok: false, error: e.code || 'ERROR', temporary: true };
    }
  };
  // one blip at the registry shouldn't lose the check, but a real "no such domain" won't change
  const { temporary, ...first } = await ask();
  if (!temporary) return first;
  const { temporary: _again, ...second } = await ask();
  return second;
}

/* ---------------- security DNS filters ---------------- */

/* Cloudflare's malware-blocking resolver answers 0.0.0.0 for domains on its lists. */
export function readCloudflare(d) {
  if (!d || typeof d.Status !== 'number') return 'unknown';
  const sunk = (d.Answer ?? []).some((a) => a.data === '0.0.0.0');
  const flagged = (d.Comment ?? []).some((c) => /EDE\((15|16|17)\)/.test(String(c)));
  return sunk || flagged ? 'blocked' : 'clean';
}

export async function cloudflareFilter(name, { json = fetchJson, deadline } = {}) {
  try {
    const r = await json(`https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, { accept: 'application/dns-json', deadline });
    return r.status === 200 ? readCloudflare(r.data) : 'unknown';
  } catch { return 'unknown'; }
}

/* A DNS question for name's A record, as raw bytes (RFC 1035) in the form DoH expects (RFC 8484). */
export function dnsQuestion(name) {
  const labels = name.split('.').map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, 'ascii')]));
  return Buffer.concat([Buffer.from([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), ...labels, Buffer.from([0, 0, 1, 0, 1])]).toString('base64url');
}

/* Quad9 answers "no such domain" for names on its threat lists. The caller only asks about sites
   that just answered us, so here that answer means blocked. Its DoH service requires HTTP/2. */
export function quad9Filter(name, { timeout = 4000 } = {}) {
  return new Promise((resolve) => {
    let client, settled = false;
    const finish = (v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { client?.destroy(); } catch { /* already gone */ }
      resolve(v);
    };
    const timer = setTimeout(() => finish('unknown'), timeout);
    try {
      client = http2.connect('https://dns.quad9.net');
      client.on('error', () => finish('unknown'));
      const req = client.request({ ':path': `/dns-query?dns=${dnsQuestion(name)}`, accept: 'application/dns-message', 'user-agent': AGENT });
      const chunks = [];
      let status = 0;
      req.on('response', (h) => { status = h[':status']; });
      req.on('data', (d) => chunks.push(d));
      req.on('error', () => finish('unknown'));
      req.on('end', () => {
        const b = Buffer.concat(chunks);
        if (status !== 200 || b.length < 12) return finish('unknown');
        const rcode = b[3] & 15;
        finish(rcode === 3 ? 'blocked' : rcode === 0 ? 'clean' : 'unknown');
      });
      req.end();
    } catch { finish('unknown'); }
  });
}

export async function reputation(name, { cloudflare = cloudflareFilter, quad9 = quad9Filter, deadline } = {}) {
  const [cf, q9] = await Promise.all([cloudflare(name, { deadline }), quad9(name)]);
  return { cloudflare: cf, quad9: q9 };
}

/* ---------------- WordPress releases ---------------- */

const WP_TTL = 6 * 3600_000;
let wpList = null;

/* 'latest', 'outdated' or 'insecure', straight from WordPress.org. null if the version isn't on its list. */
export async function wordpressStatus(version, { json = fetchJson, deadline, now = Date.now() } = {}) {
  try {
    if (!wpList || now - wpList.at > WP_TTL) {
      const r = await json('https://api.wordpress.org/core/stable-check/1.0/', { deadline });
      if (r.status !== 200 || !r.data) return null;
      wpList = { at: now, versions: r.data };
    }
    const status = wpList.versions[version];
    return typeof status === 'string' ? status : null;
  } catch { return null; }
}
export const _resetWordpress = () => { wpList = null; };

/* ---------------- DKIM keys ---------------- */

const SELECTORS_BY_MAIL = [
  [/google\.com|googlemail\.com/, ['google']], [/outlook\.com/, ['selector1', 'selector2']], [/zoho\./, ['zoho', 'zmail']],
  [/protonmail\.ch/, ['protonmail', 'protonmail2', 'protonmail3']], [/messagingengine\.com/, ['fm1', 'fm2', 'fm3']], [/icloud\.com/, ['sig1']],
];
const COMMON_SELECTORS = ['default', 'dkim', 'mail', 'k1', 's1', 's2'];

/* DKIM keys live under a name the mail provider picks, and DNS can't list them, so this tries the
   usual names. Finding one proves it exists; finding none proves nothing, so it never costs points. */
export async function dkimKeys(domain, mx = [], resolver) {
  const hosts = mx.join(' ');
  const selectors = new Set([...SELECTORS_BY_MAIL.filter(([re]) => re.test(hosts)).flatMap(([, s]) => s), ...COMMON_SELECTORS]);
  const found = [];
  await Promise.all([...selectors].map(async (s) => {
    try {
      const recs = await resolver.resolveTxt(`${s}._domainkey.${domain}`);
      if (recs.some((parts) => /(^|;\s*)(v=DKIM1|k=rsa|p=[A-Za-z0-9+/])/i.test(parts.join('')))) found.push(s);
    } catch { /* not here */ }
  }));
  return { ok: true, found: found.sort() };
}
