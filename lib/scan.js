/* One scan, start to finish, shared by the web API, the badge, the CLI and the MCP server. */
import { normalizeTarget } from './guard.js';
import { inspect } from './inspect.js';
import { evaluate, unreachable } from './checks.js';

const TTL = 120_000, MAX_CACHED = 500;
export const cache = new Map();

/* Returns the report ({ ok: true, ... }) or { ok: false, status, error } in plain English. Never throws. */
export async function scanTarget(target, { fresh = false, onStep, run = inspect, now = Date.now } = {}) {
  const hit = cache.get(target.host);
  if (!fresh && hit && now() - hit.at < TTL) return hit.report;
  try {
    const obs = await run(target, { onStep });
    const stop = unreachable(obs);
    if (stop) return { ok: false, status: 422, error: stop };
    const report = { ok: true, ...evaluate(obs) };
    cache.delete(target.host);
    cache.set(target.host, { at: now(), report });
    if (cache.size > MAX_CACHED) cache.delete(cache.keys().next().value);
    return report;
  } catch {
    return { ok: false, status: 502, error: 'Something went wrong while checking that site. Try again in a moment.' };
  }
}

/* The same, starting from whatever someone typed. */
export async function scanAddress(input, options) {
  let target;
  try {
    target = normalizeTarget(input);
  } catch (e) {
    return { ok: false, status: 400, error: e.expose ? e.message : 'Send a website address to check.' };
  }
  return scanTarget(target, options);
}
