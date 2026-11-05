/* Observation builders: the shape inspect() returns, with sensible defaults to override. */
export const NOW = Date.parse('2026-10-27T12:00:00Z');
const DAY = 86400000;

export const STRONG = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
};

export function site({ host = 'shop.example.com', headers = {}, body = '<!doctype html><title>Shop</title><p>Hi</p>', days = 90, https = {}, http = {}, dns = {}, www = {}, rep = {}, rdap = {}, wp = null, dkim = {} } = {}) {
  const domain = host.replace(/^www\./, '');
  return {
    host, domain, fetchedAt: new Date(NOW).toISOString(),
    https: {
      ok: true, status: 200, url: `https://${host}/`, chain: [{ url: `https://${host}/`, status: 200 }],
      headers: { 'content-type': 'text/html; charset=utf-8', ...headers }, body,
      cert: days === null ? null : { validTo: new Date(NOW + days * DAY).toISOString(), issuer: "Let's Encrypt", subject: host },
      ...https,
    },
    http: { ok: true, status: 301, url: `http://${host}/`, chain: [{ url: `http://${host}/`, status: 301 }], headers: {}, next: `https://${host}/`, ...http },
    dns: { ok: true, spf: ['v=spf1 include:_spf.google.com ~all'], spfAt: domain, dmarc: ['v=DMARC1; p=quarantine'], dmarcAt: domain, mx: ['aspmx.l.google.com'], ...dns },
    www: { applies: true, host: `www.${domain}`, ok: true, status: 200, ...www },
    rep: { cloudflare: 'clean', quad9: 'clean', ...rep },
    rdap: { ok: true, expires: new Date(NOW + 400 * DAY).toISOString(), created: '2015-03-02T00:00:00.000Z', registrar: 'Namecheap, Inc.', status: ['client transfer prohibited'], ...rdap },
    wp,
    dkim: { ok: true, found: ['google'], ...dkim },
  };
}

export const byId = (report) => Object.fromEntries(report.checks.map((c) => [c.id, c]));
