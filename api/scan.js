/* POST /api/scan { url } -> the graded report. Runs as a Vercel function and under server.js.
   Basic abuse limits live here: small bodies, a per-visitor rate limit, and a short cache so the
   same site isn't fetched again and again. Results are never written anywhere. */
import { normalizeTarget } from '../lib/guard.js';
import { inspect } from '../lib/inspect.js';
import { evaluate, unreachable } from '../lib/checks.js';

const LIMIT = 8, WINDOW = 60_000, TTL = 120_000;
const hits = new Map(), cache = new Map();

function send(res, status, body, extra = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra })) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

function visitor(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

function limited(ip, now = Date.now()) {
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) for (const [k, v] of hits) if (now - v.at(-1) > WINDOW) hits.delete(k);
  return recent.length > LIMIT;
}

async function readJson(req, max = 4096) {
  if (req.body !== undefined) return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;   // Vercel pre-parses
  let size = 0;
  const chunks = [];
  for await (const c of req) { size += c.length; if (size > max) throw new Error('too big'); chunks.push(c); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'Use POST.' }, { allow: 'POST' });
  if (limited(visitor(req))) return send(res, 429, { ok: false, error: 'Too many checks in a row. Try again in a minute.' }, { 'retry-after': '60' });
  let target;
  try {
    target = normalizeTarget((await readJson(req))?.url);
  } catch (e) {
    return send(res, 400, { ok: false, error: e.expose ? e.message : 'Send a website address to check.' });
  }
  const hit = cache.get(target.host);
  if (hit && Date.now() - hit.at < TTL) return send(res, 200, hit.report);
  try {
    const obs = await inspect(target);
    const stop = unreachable(obs);
    if (stop) return send(res, 422, { ok: false, error: stop });
    const report = { ok: true, ...evaluate(obs) };
    cache.set(target.host, { at: Date.now(), report });
    if (cache.size > 500) cache.delete(cache.keys().next().value);
    return send(res, 200, report);
  } catch {
    return send(res, 502, { ok: false, error: 'Something went wrong while checking that site. Try again in a moment.' });
  }
}

export const _test = { hits, cache };
