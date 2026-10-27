/* Collects what any visitor's browser could see: the homepage over https (following redirects),
   the plain-http answer, the certificate, and the domain's public email records.
   Read-only by design: GET "/" only, small bodies, short timeouts, one overall deadline. */
import http from 'node:http';
import https from 'node:https';
import { Resolver } from 'node:dns/promises';
import { guardedLookup, assertPublicUrl } from './guard.js';

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36 DARE-CHECK/1.0';
const CERT_ERRORS = new Set([
  'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'ERR_TLS_CERT_ALTNAME_INVALID',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT', 'CERT_NOT_YET_VALID',
]);
const MAX_HOPS = 5;

/* One GET. Resolves with status, headers, the first maxBytes of the body and (for https) the cert. */
export function get(url, { lookup = guardedLookup, timeout = 7000, maxBytes = 262144, insecure = false } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    let started = false;
    const req = mod.request(u, {
      method: 'GET', agent: false, lookup, timeout, rejectUnauthorized: !insecure,
      headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8', 'accept-language': 'en-US,en;q=0.8' },
    }, (res) => {
      started = true;
      let cert = null;
      if (u.protocol === 'https:') {
        const c = res.socket.getPeerCertificate?.();
        if (c && c.valid_to) cert = { validTo: new Date(c.valid_to).toISOString(), issuer: c.issuer?.O || c.issuer?.CN || '', subject: c.subject?.CN || '' };
      }
      const chunks = [];
      let size = 0;
      const done = () => { clearTimeout(hard); resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), cert }); };
      res.on('data', (d) => { size += d.length; if (size <= maxBytes) chunks.push(d); else res.destroy(); });
      res.on('end', done);
      res.on('close', done);   // still resolves after destroy() at the size cap
      res.on('error', done);
    });
    // `timeout` above only fires when the socket goes idle, so a server dripping a byte at a time
    // could outlast any deadline. This hard cap ends the request regardless: mid-body it keeps what
    // already arrived (the headers are what matter), before any response it fails.
    const timedOut = () => Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
    const hard = setTimeout(() => (started ? req.destroy() : req.destroy(timedOut())), timeout);
    req.on('timeout', () => req.destroy(timedOut()));
    req.on('error', (e) => { clearTimeout(hard); reject(e); });
    req.end();
  });
}

const left = (deadline) => Math.max(500, Math.min(7000, deadline - Date.now()));

/* Follow redirects by hand so every hop goes through the guard. stopAtHttps ends the walk as soon
   as a redirect points at https (that's all the plain-http check needs to know). */
export async function fetchChain(start, { deadline = Date.now() + 15000, stopAtHttps = false, ...opts } = {}) {
  const chain = [];
  let cur = new URL(start);
  for (let hop = 0; hop <= MAX_HOPS; hop++) {
    assertPublicUrl(cur, opts);
    if (Date.now() > deadline) throw Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });
    const r = await get(cur.href, { ...opts, timeout: left(deadline) });
    chain.push({ url: cur.href, status: r.status });
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc) {
      const next = new URL(loc, cur);
      if (stopAtHttps && next.protocol === 'https:') return { ...r, url: cur.href, chain, next: next.href };
      cur = next;
      continue;
    }
    return { ...r, url: cur.href, chain };
  }
  throw Object.assign(new Error('too many redirects'), { code: 'EREDIRECTS', chain });
}

const pick = (r) => ({ status: r.status, url: r.url, chain: r.chain, headers: r.headers, body: r.body, cert: r.cert, next: r.next });

async function secure(host, opts) {
  try {
    return { ok: true, ...pick(await fetchChain(`https://${host}/`, opts)) };
  } catch (e) {
    const out = { ok: false, error: e.code || 'ERROR' };
    // a bad certificate still has headers and an expiry date worth reporting
    if (CERT_ERRORS.has(e.code)) {
      try { Object.assign(out, pick(await fetchChain(`https://${host}/`, { ...opts, insecure: true }))); } catch { /* nothing more to learn */ }
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

export function makeResolver() {
  return new Resolver({ timeout: 3000, tries: 2 });
}

export async function emailRecords(domain, resolver = makeResolver()) {
  const none = (e) => ['ENODATA', 'ENOTFOUND', 'ENOTIMP'].includes(e.code);
  const txt = async (name) => {
    try { return (await resolver.resolveTxt(name)).map((parts) => parts.join('')); } catch (e) { if (none(e)) return []; throw e; }
  };
  try {
    const [root, mx] = await Promise.all([
      txt(domain),
      resolver.resolveMx(domain).catch((e) => { if (none(e)) return []; throw e; }),
    ]);
    // DMARC can live on the organisational domain, so walk up one label at a time
    let dmarc = [], dmarcAt = null;
    for (let d = domain; d.split('.').length >= 2; d = d.split('.').slice(1).join('.')) {
      const recs = (await txt('_dmarc.' + d)).filter((r) => /^v=DMARC1\b/i.test(r));
      if (recs.length) { dmarc = recs; dmarcAt = d; break; }
    }
    return {
      ok: true,
      spf: root.filter((r) => /^v=spf1(\s|$)/i.test(r)),
      dmarc, dmarcAt,
      mx: mx.sort((a, b) => a.priority - b.priority).map((m) => m.exchange.toLowerCase()),
    };
  } catch (e) {
    return { ok: false, error: e.code || 'ERROR' };
  }
}

export async function inspect({ host, domain }, { resolver = makeResolver(), ...opts } = {}) {
  const deadline = Date.now() + 15000;
  const [sec, pl, mail] = await Promise.all([secure(host, { ...opts, deadline }), plain(host, { ...opts, deadline }), emailRecords(domain, resolver)]);
  return { host, domain, fetchedAt: new Date().toISOString(), https: sec, http: pl, dns: mail };
}
