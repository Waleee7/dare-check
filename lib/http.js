/* The one way DARE CHECK talks to the web: GET only, small bodies, short timeouts, redirects walked
   by hand, and every connection checked by the SSRF guard. */
import http from 'node:http';
import https from 'node:https';
import { guardedLookup, assertPublicUrl } from './guard.js';

const UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130 Safari/537.36 DARE-CHECK/1.0';
const BROWSER = { 'user-agent': UA, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8', 'accept-language': 'en-US,en;q=0.8' };
const MAX_HOPS = 5;

/* One GET. Resolves with status, headers, the first maxBytes of the body and (for https) the cert. */
export function get(url, { lookup = guardedLookup, timeout = 7000, maxBytes = 262144, insecure = false, headers = BROWSER } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    let started = false;
    const req = mod.request(u, { method: 'GET', agent: false, lookup, timeout, rejectUnauthorized: !insecure, headers }, (res) => {
      started = true;
      let cert = null, tls = null;
      if (u.protocol === 'https:') {
        const c = res.socket.getPeerCertificate?.();
        if (c && c.valid_to) cert = { validTo: new Date(c.valid_to).toISOString(), issuer: c.issuer?.O || c.issuer?.CN || '', subject: c.subject?.CN || '' };
        tls = res.socket.getProtocol?.() ?? null;
      }
      const chunks = [];
      let size = 0;
      const done = () => { clearTimeout(hard); resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), cert, tls }); };
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
