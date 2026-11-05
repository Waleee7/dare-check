/* POST /api/scan { url, fresh? } -> the graded report. Runs as a Vercel function and under server.js.
   Ask with `Accept: application/x-ndjson` to get each step as it finishes, one JSON object per line,
   ending in { type: 'report' } or { type: 'error' }. Results are never written anywhere. */
import { normalizeTarget } from '../lib/guard.js';
import { scanTarget, cache } from '../lib/scan.js';
import { limited, visitor, hits } from '../lib/limit.js';

function send(res, status, body, extra = {}) {
  res.statusCode = status;
  for (const [k, v] of Object.entries({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra })) res.setHeader(k, v);
  res.end(JSON.stringify(body));
}

async function readJson(req, max = 4096) {
  if (req.body !== undefined) return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;   // Vercel pre-parses
  let size = 0;
  const chunks = [];
  for await (const c of req) { size += c.length; if (size > max) throw new Error('too big'); chunks.push(c); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

export function createHandler({ run } = {}) {
  return async function handler(req, res) {
    if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'Use POST.' }, { allow: 'POST' });
    // JSON can't be sent cross-site without a CORS preflight, which this API never grants
    if (!/^application\/json\b/i.test(String(req.headers['content-type'] || ''))) return send(res, 415, { ok: false, error: 'Send the address as JSON.' });
    if (limited(visitor(req))) return send(res, 429, { ok: false, error: 'Too many checks in a row. Try again in a minute.' }, { 'retry-after': '60' });
    let target, fresh = false;
    try {
      const input = await readJson(req);
      target = normalizeTarget(input?.url);
      fresh = input?.fresh === true;
    } catch (e) {
      return send(res, 400, { ok: false, error: e.expose ? e.message : 'Send a website address to check.' });
    }

    if (!/application\/x-ndjson/i.test(String(req.headers.accept || ''))) {
      const out = await scanTarget(target, { fresh, run });
      if (out.ok) return send(res, 200, out);
      return send(res, out.status, { ok: false, error: out.error });
    }

    res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store, no-transform', 'x-content-type-options': 'nosniff', 'x-accel-buffering': 'no' });
    const line = (o) => res.write(JSON.stringify(o) + '\n');
    const out = await scanTarget(target, { fresh, run, onStep: (s) => line({ type: 'step', ...s }) });
    line(out.ok ? { type: 'report', report: out } : { type: 'error', error: out.error });
    res.end();
  };
}

export default createHandler();

export const _test = { hits, cache };
