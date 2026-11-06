import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRdap, domainRecord, readCloudflare, cloudflareFilter, dnsQuestion, reputation, wordpressStatus, _resetWordpress, dkimKeys } from '../lib/sources.js';
import { registrable, wwwVariant, sharedSuffix } from '../lib/domains.js';

const RDAP = {
  ldhName: 'EXAMPLE.COM', status: ['client delete prohibited', 'client transfer prohibited'],
  events: [{ eventAction: 'registration', eventDate: '2007-10-09T18:20:50Z' }, { eventAction: 'expiration', eventDate: '2028-10-09T18:20:50Z' }],
  entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]] }, { roles: ['abuse'] }],
};

test('registrable domain: subdomains, country second levels, and already-short names', () => {
  const cases = [['shop.example.com', 'example.com'], ['example.com', 'example.com'], ['a.b.example.co.uk', 'example.co.uk'], ['example.com.au', 'example.com.au'],
    ['x.example.de', 'example.de'], ['blog.example.io', 'example.io'], ['www.example.org', 'example.org'], ['co.uk', 'co.uk']];
  for (const [input, want] of cases) assert.equal(registrable(input), want, input);
});

test('www spelling: only offered for a main domain, in the direction not typed', () => {
  assert.equal(wwwVariant('example.com'), 'www.example.com');
  assert.equal(wwwVariant('www.example.com'), 'example.com');
  assert.equal(wwwVariant('example.co.uk'), 'www.example.co.uk');
  assert.equal(wwwVariant('shop.example.com'), null);
  assert.equal(wwwVariant('mysite.vercel.app'), null);
  assert.equal(sharedSuffix('mysite.vercel.app'), 'vercel.app');
  assert.equal(sharedSuffix('notvercel.app'), null);
});

test('RDAP parsing pulls dates, registrar and status, and survives junk', () => {
  const r = parseRdap(RDAP);
  assert.equal(r.expires, '2028-10-09T18:20:50.000Z');
  assert.equal(r.created, '2007-10-09T18:20:50.000Z');
  assert.equal(r.registrar, 'MarkMonitor Inc.');
  assert.deepEqual(r.status, ['client delete prohibited', 'client transfer prohibited']);
  for (const junk of [{}, { events: 'x', entities: 5, status: 'y' }, { events: [{ eventAction: 'expiration', eventDate: 'soon' }] }, { entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', { evil: 1 }]]] }] }]) {
    const out = parseRdap(junk);
    assert.equal(out.ok, true);
    assert.equal(out.expires, null);
    assert.equal(out.registrar, null);
  }
});

test('domainRecord asks the right registry, and fails soft', async () => {
  const seen = [];
  const json = async (url, o) => { seen.push([url, o.accept]); return { status: 200, data: RDAP }; };
  await domainRecord('example.com', { json });
  await domainRecord('example.org', { json });
  await domainRecord('example.app', { json });
  assert.deepEqual(seen.map((s) => s[0]), ['https://rdap.verisign.com/com/v1/domain/example.com', 'https://rdap.publicinterestregistry.org/rdap/domain/example.org', 'https://rdap.org/domain/example.app']);
  assert.equal(seen[0][1], 'application/rdap+json');
  assert.deepEqual(await domainRecord('example.io', { json: async () => ({ status: 404, data: null }) }), { ok: false, error: 'HTTP 404' });
  assert.deepEqual(await domainRecord('example.com', { json: async () => { throw Object.assign(new Error('x'), { code: 'ETIMEDOUT' }); } }), { ok: false, error: 'ETIMEDOUT' });
});

test('Cloudflare filter: 0.0.0.0 or a censored comment means blocked, odd answers mean unknown', async () => {
  assert.equal(readCloudflare({ Status: 0, Answer: [{ data: '140.82.114.4' }] }), 'clean');
  assert.equal(readCloudflare({ Status: 0, Answer: [{ data: '0.0.0.0' }], Comment: ['EDE(16): Censored'] }), 'blocked');
  assert.equal(readCloudflare({ Status: 0, Comment: ['EDE(16): Censored'] }), 'blocked');
  assert.equal(readCloudflare({ Status: 0 }), 'clean', 'no A record (an IPv6-only site) is not a block');
  assert.equal(readCloudflare(null), 'unknown');
  assert.equal(readCloudflare({ html: true }), 'unknown');
  assert.equal(await cloudflareFilter('x.example.com', { json: async () => ({ status: 500, data: null }) }), 'unknown');
  assert.equal(await cloudflareFilter('x.example.com', { json: async () => { throw new Error('down'); } }), 'unknown');
  const seen = [];
  await cloudflareFilter('shop.example.com', { json: async (u, o) => { seen.push(u, o.accept); return { status: 200, data: { Status: 0 } }; } });
  assert.deepEqual(seen, ['https://security.cloudflare-dns.com/dns-query?name=shop.example.com&type=A', 'application/dns-json']);
});

test('the DNS question is well-formed wire format', () => {
  const b = Buffer.from(dnsQuestion('a.bc'), 'base64url');
  assert.deepEqual([...b], [0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 97, 2, 98, 99, 0, 0, 1, 0, 1]);
});

test('reputation asks both filters and reports each one', async () => {
  const r = await reputation('x.example.com', { cloudflare: async () => 'clean', quad9: async () => 'blocked' });
  assert.deepEqual(r, { cloudflare: 'clean', quad9: 'blocked' });
});

test('WordPress status comes from the official list, which is fetched once and refreshed', async () => {
  _resetWordpress();
  let calls = 0;
  const json = async () => { calls++; return { status: 200, data: { '6.0': 'insecure', '7.1.4': 'latest' } }; };
  assert.equal(await wordpressStatus('6.0', { json, now: 1000 }), 'insecure');
  assert.equal(await wordpressStatus('7.1.4', { json, now: 2000 }), 'latest');
  assert.equal(await wordpressStatus('9.9.9', { json, now: 3000 }), null, 'a version not on the list says nothing');
  assert.equal(calls, 1);
  await wordpressStatus('6.0', { json, now: 1000 + 7 * 3600_000 });
  assert.equal(calls, 2);
  _resetWordpress();
  assert.equal(await wordpressStatus('6.0', { json: async () => { throw new Error('down'); } }), null);
  assert.equal(await wordpressStatus('6.0', { json: async () => ({ status: 503, data: null }) }), null);
  _resetWordpress();
});

test('DKIM: tries the provider\'s usual names, recognizes real keys, ignores everything else', async () => {
  const asked = [];
  const resolver = {
    resolveTxt: async (name) => {
      asked.push(name);
      if (name === 'google._domainkey.example.com') return [['v=DKIM1; k=rsa; p=MIIBIjAN', 'BgkqhkiG9w0']];
      if (name === 'mail._domainkey.example.com') return [['not a key at all']];
      throw Object.assign(new Error('none'), { code: 'ENODATA' });
    },
  };
  const r = await dkimKeys('example.com', ['aspmx.l.google.com'], resolver);
  assert.deepEqual(r, { ok: true, found: ['google'] });
  assert.ok(asked.includes('google._domainkey.example.com'));
  assert.ok(!asked.includes('selector1._domainkey.example.com'), "only Microsoft's names for Microsoft mail");
  const ms = await dkimKeys('example.com', ['x.mail.protection.outlook.com'], { resolveTxt: async (n) => { if (n.startsWith('selector1.')) return [['v=DKIM1; p=abc']]; throw new Error('none'); } });
  assert.deepEqual(ms.found, ['selector1']);
});

test('domainRecord tries twice after a blip, but takes a real answer the first time', async () => {
  const replies = (...rs) => { let n = 0; const json = async () => { const r = rs[n++]; if (r instanceof Error) throw r; return r; }; return { json, calls: () => n }; };
  const good = { status: 200, data: { events: [{ eventAction: 'expiration', eventDate: '2030-01-01T00:00:00Z' }] } };
  for (const blip of [Object.assign(new Error('reset'), { code: 'ECONNRESET' }), { status: 503 }, { status: 429 }]) {
    const a = replies(blip, good);
    const r = await domainRecord('example.com', { json: a.json });
    assert.equal(r.ok, true);
    assert.equal(a.calls(), 2);
  }
  const twice = replies({ status: 503 }, { status: 503 });
  assert.equal((await domainRecord('example.com', { json: twice.json })).ok, false);
  assert.equal(twice.calls(), 2);
  const missing = replies({ status: 404 });
  assert.equal((await domainRecord('example.com', { json: missing.json })).error, 'HTTP 404');
  assert.equal(missing.calls(), 1);
  const first = replies(good);
  await domainRecord('example.com', { json: first.json });
  assert.equal(first.calls(), 1);
});
