/* Per-visitor rate limit. Lives in the function instance's memory, which is enough to slow one
   person down on a free tool; it isn't a substitute for a firewall under real attack. */
export const LIMIT = 8;
const WINDOW = 60_000;
export const hits = new Map();

export function visitor(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return req.headers['x-vercel-forwarded-for'] || fwd || req.headers['x-real-ip'] || req.socket?.remoteAddress || 'unknown';
}

export function limited(ip, now = Date.now()) {
  const recent = (hits.get(ip) || []).filter((t) => now - t < WINDOW);
  recent.push(now);
  hits.set(ip, recent);
  if (hits.size > 5000) for (const [k, v] of hits) if (now - v.at(-1) > WINDOW) hits.delete(k);
  return recent.length > LIMIT;
}
