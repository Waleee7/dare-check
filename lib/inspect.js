/* Collects what any visitor's browser could see: the homepage over https (following redirects), the
   plain-http answer, the www spelling, the certificate and the domain's public records.
   Read-only by design: GET "/" only, small bodies, short timeouts, one overall deadline.
   onStep reports each part as it finishes, so the page can show real progress. */
import { Resolver } from 'node:dns/promises';
import { get, fetchChain } from './http.js';
import { registrable, sharedSuffix, wwwVariant } from './domains.js';
import { parsePage, wordpressVersion } from './html.js';
import { reputation, domainRecord, wordpressStatus, dkimKeys } from './sources.js';

export { get, fetchChain };

const CERT_ERRORS = new Set([
  'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT', 'CERT_NOT_YET_VALID',
]);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const BLIPS = new Set(['ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN']);

/* A site that says "too busy", or a connection that drops, gets one more polite try before we
   believe it. A network blip must not grade a working site F. */
export async function politeFetch(url, { retryAfter = 1200, ...opts } = {}) {
  const roomLeft = () => !opts.deadline || Date.now() + retryAfter + 500 <= opts.deadline;
  let first;
  try {
    first = await fetchChain(url, opts);
  } catch (e) {
    if (!BLIPS.has(e.code) || !roomLeft()) throw e;
    await sleep(retryAfter);
    return fetchChain(url, opts);
  }
  if (![429, 503].includes(first.status) || !roomLeft()) return first;
  await sleep(retryAfter);
  try { return await fetchChain(url, opts); } catch { return first; }
}

const pick = (r) => ({ status: r.status, url: r.url, chain: r.chain, headers: r.headers, body: r.body, cert: r.cert, tls: r.tls, next: r.next });

async function secure(host, opts) {
  try {
    return { ok: true, ...pick(await politeFetch(`https://${host}/`, opts)) };
  } catch (e) {
    const out = { ok: false, error: e.code || 'ERROR' };
    // a bad certificate still has headers and an expiry date worth reporting
    if (CERT_ERRORS.has(e.code)) {
      try { Object.assign(out, pick(await politeFetch(`https://${host}/`, { ...opts, insecure: true }))); } catch { /* nothing more to learn */ }
    }
    return out;
  }
}

async function plain(host, opts) {
  try {
    return { ok: true, ...pick(await fetchChain(`http://${host}/`, { ...opts, stopAtHttps: true })) };
  } catch (e) {
    return { ok: false, error: e.code || 'ERROR' };
  }
}

async function otherSpelling(host, opts) {
  const other = wwwVariant(host);
  if (!other) return { applies: false };
  try {
    const r = await fetchChain(`https://${other}/`, opts);
    return { applies: true, host: other, ok: true, status: r.status };
  } catch (e) {
    return { applies: true, host: other, ok: false, error: e.code || 'ERROR' };
  }
}

export function makeResolver() {
  return new Resolver({ timeout: 3000, tries: 2 });
}

export async function emailRecords(domain, resolver = makeResolver()) {
  const none = (e) => ['ENODATA', 'ENOTFOUND', 'ENOTIMP'].includes(e.code);
  const txt = async (name) => {
    try { return (await resolver.resolveTxt(name)).map((parts) => parts.join('')); } catch (e) { if (none(e)) return []; throw e; }
  };
  const mxOf = (name) => resolver.resolveMx(name).catch((e) => { if (none(e)) return []; throw e; });
  const isSpf = (r) => /^v=spf1(\s|$)/i.test(r);
  const org = registrable(domain);
  try {
    const [root, mx] = await Promise.all([txt(domain), mxOf(domain)]);
    let spf = root.filter(isSpf), spfAt = spf.length ? domain : null, mail = mx;
    // a subdomain usually borrows the main domain's email setup, so read that before judging it
    if (org !== domain && (!spf.length || !mail.length)) {
      const [orgTxt, orgMx] = await Promise.all([txt(org), mxOf(org)]);
      if (!spf.length) { spf = orgTxt.filter(isSpf); spfAt = spf.length ? org : null; }
      if (!mail.length) mail = orgMx;
    }
    // DMARC can live on the organisational domain, so walk up one label at a time
    let dmarc = [], dmarcAt = null;
    for (let d = domain; d.split('.').length >= 2; d = d.split('.').slice(1).join('.')) {
      const recs = (await txt('_dmarc.' + d)).filter((r) => /^v=DMARC1\b/i.test(r));
      if (recs.length) { dmarc = recs; dmarcAt = d; break; }
    }
    return { ok: true, org, spf, spfAt, dmarc, dmarcAt, mx: mail.sort((a, b) => a.priority - b.priority).map((m) => m.exchange.toLowerCase()) };
  } catch (e) {
    return { ok: false, error: e.code || 'ERROR' };
  }
}

const within = (promise, ms, fallback) => new Promise((resolve) => {
  const t = setTimeout(() => resolve(fallback), ms);
  promise.then((v) => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve(fallback); });
});

const shortDate = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const TLS_NAME = { 'TLSv1.3': 'TLS 1.3', 'TLSv1.2': 'TLS 1.2', 'TLSv1.1': 'TLS 1.1', TLSv1: 'TLS 1.0' };

export async function inspect({ host, domain }, { resolver = makeResolver(), onStep = () => {}, lookups = {}, ...opts } = {}) {
  const deadline = Date.now() + 15000;
  const { rep = reputation, record = domainRecord, wp = wordpressStatus, dkim = dkimKeys } = lookups;
  const step = (id, note) => { try { onStep({ id, note }); } catch { /* a closed connection can't stop the scan */ } };
  const shared = sharedSuffix(domain);

  const sec = secure(host, { ...opts, deadline }).then((s) => {
    step('https', s.ok ? [TLS_NAME[s.tls] ?? s.tls, `status ${s.status}`].filter(Boolean).join(' · ') : "couldn't connect securely");
    step('cert', s.cert ? [s.cert.issuer, `expires ${shortDate(s.cert.validTo)}`].filter(Boolean).join(' · ') : 'no certificate to read');
    return s;
  });
  // the homepage first, then the rest, so a small site never sees a burst of requests from us
  const pl = sec.then(() => plain(host, { ...opts, deadline })).then((p) => {
    step('http', !p.ok ? 'no answer on plain http' : p.next ? 'forwards to https' : `answers with status ${p.status}`);
    return p;
  });
  const alt = sec.then(() => otherSpelling(host, { ...opts, deadline })).then((w) => {
    step('www', !w.applies ? "doesn't apply here" : w.ok ? `${w.host} answers` : `${w.host} failed`);
    return w;
  });
  const mail = emailRecords(domain, resolver).then((d) => {
    step('email', !d.ok ? "couldn't read DNS" : `SPF ${d.spf.length ? 'found' : 'missing'} · DMARC ${d.dmarc.length ? 'found' : 'missing'}`);
    return d;
  });
  const keys = mail.then((d) => (d.ok && !shared ? within(dkim(d.org ?? domain, d.mx, resolver), 6000, { ok: false }) : { ok: false })).then((k) => {
    step('dkim', k.found?.length ? `key at ${k.found[0]}` : k.ok ? 'none at the usual names' : 'skipped');
    return k;
  });
  const listed = within(rep(host, { deadline }), 8000, { cloudflare: 'unknown', quad9: 'unknown' }).then((r) => {
    const blocked = r.cloudflare === 'blocked' || r.quad9 === 'blocked';
    step('blocklist', blocked ? 'listed' : r.cloudflare === 'unknown' && r.quad9 === 'unknown' ? "couldn't reach the filters" : 'not listed');
    return r;
  });
  const reg = (shared ? Promise.resolve({ ok: false, error: 'SHARED' }) : within(record(registrable(domain), { deadline }), 8000, { ok: false, error: 'ETIMEDOUT' })).then((r) => {
    step('domain', r.ok && r.expires ? `renews by ${shortDate(r.expires)}` : shared ? 'owned by the platform' : "registry didn't say");
    return r;
  });
  const soft = sec.then(async (s) => {
    const version = s.headers ? wordpressVersion(parsePage(s.body)) : null;
    const status = version ? await within(wp(version, { deadline }), 6000, null) : null;
    step('software', version ? `WordPress ${version}` : 'read the page');
    return version ? { version, status } : null;
  });

  const [https, http, www, dns, dkimResult, repResult, rdap, wpResult] = await Promise.all([sec, pl, alt, mail, keys, listed, reg, soft]);
  return { host, domain, fetchedAt: new Date().toISOString(), https, http, www, dns, dkim: dkimResult, rep: repResult, rdap, wp: wpResult };
}
