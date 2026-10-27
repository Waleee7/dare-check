/* The fetcher against real local servers. A test-only lookup maps every name to 127.0.0.1 so the
   redirect and size logic can run offline; the default (guarded) lookup is tested on its own. */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { get, fetchChain, emailRecords } from '../lib/inspect.js';

const toLocal = (host, opts, cb) => {
  if (typeof opts === 'function') { cb = opts; opts = {}; }
  if (opts.all) cb(null, [{ address: '127.0.0.1', family: 4 }]); else cb(null, '127.0.0.1', 4);
};

const server = http.createServer((req, res) => {
  const go = (to, code = 301) => { res.writeHead(code, { location: to }); res.end(); };
  if (req.url === '/') return go('/two');
  if (req.url === '/two') return go(`http://second.test:${port}/final`, 302);
  if (req.url === '/final') { res.writeHead(200, { 'content-type': 'text/html', 'x-frame-options': 'DENY', 'set-cookie': ['a=1; Secure', 'b=2'] }); return res.end('<p>done</p>'); }
  if (req.url === '/loop') return go('/loop');
  if (req.url === '/to-https') return go('https://secure.test/');
  if (req.url === '/to-ip') return go(`http://127.0.0.1:${port}/final`);
  if (req.url === '/big') { res.writeHead(200, { 'content-type': 'text/html' }); return res.end('x'.repeat(1_000_000)); }
  if (req.url === '/slow') return;   // never answers
  if (req.url === '/drip') {         // headers at once, then one byte every 100 ms forever
    res.writeHead(200, { 'content-type': 'text/html', 'x-frame-options': 'DENY' });
    const t = setInterval(() => res.write('.'), 100);
    return res.on('close', () => clearInterval(t));
  }
  res.writeHead(404); res.end();
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
after(() => { server.closeAllConnections(); server.close(); });

const opts = { lookup: toLocal, allowPorts: true };

test('follows a redirect chain across hosts and returns the final page', async () => {
  const r = await fetchChain(`http://first.test:${port}/`, opts);
  assert.deepEqual(r.chain.map((c) => c.status), [301, 302, 200]);
  assert.equal(r.url, `http://second.test:${port}/final`);
  assert.equal(r.headers['x-frame-options'], 'DENY');
  assert.deepEqual(r.headers['set-cookie'], ['a=1; Secure', 'b=2']);
  assert.equal(r.body, '<p>done</p>');
});

test('redirect loops stop after five hops', async () => {
  await assert.rejects(fetchChain(`http://first.test:${port}/loop`, opts), { code: 'EREDIRECTS' });
});

test('stopAtHttps reports where plain http sends visitors without fetching it', async () => {
  const r = await fetchChain(`http://first.test:${port}/to-https`, { ...opts, stopAtHttps: true });
  assert.equal(r.next, 'https://secure.test/');
  assert.equal(r.status, 301);
});

test('a redirect to a private IP literal is refused even though it skips DNS', async () => {
  await assert.rejects(fetchChain(`http://first.test:${port}/to-ip`, opts), { code: 'EBLOCKED' });
});

test('the default guarded lookup refuses localhost', async () => {
  await assert.rejects(get(`http://localhost:${port}/final`), { code: 'EBLOCKED' });
});

test('bodies are capped and slow servers time out', async () => {
  const big = await get(`http://first.test:${port}/big`, { lookup: toLocal, maxBytes: 50_000 });
  assert.ok(big.body.length <= 50_000 + 65_536, `body ${big.body.length}`);
  await assert.rejects(get(`http://first.test:${port}/slow`, { lookup: toLocal, timeout: 300 }), { code: 'ETIMEDOUT' });
});

test('a server dripping bytes cannot outlast the hard per-request cap', async () => {
  const t0 = Date.now();
  const r = await get(`http://first.test:${port}/drip`, { lookup: toLocal, timeout: 600 });
  const took = Date.now() - t0;
  assert.ok(took < 1500, `took ${took} ms`);
  assert.equal(r.headers['x-frame-options'], 'DENY', 'the headers that arrived are kept');
  assert.ok(r.body.length > 0 && r.body.length < 20, `kept ${r.body.length} bytes`);
});

test('a self-signed certificate is reported as untrusted, and still read when asked', async (t) => {
  let dir;
  try {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dare-check-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=secure.test',
      '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { stdio: 'ignore' });
  } catch { return t.skip('openssl not available'); }
  const tlsServer = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) }, (req, res) => { res.writeHead(200, { 'strict-transport-security': 'max-age=60' }); res.end('ok'); });
  await new Promise((r) => tlsServer.listen(0, '127.0.0.1', r));
  const url = `https://secure.test:${tlsServer.address().port}/`;
  try {
    await assert.rejects(get(url, { lookup: toLocal }), { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' });
    const r = await get(url, { lookup: toLocal, insecure: true });
    assert.equal(r.status, 200);
    assert.equal(r.cert.subject, 'secure.test');
    assert.ok(Date.parse(r.cert.validTo) > Date.now(), 'expiry date read from the certificate');
  } finally {
    tlsServer.closeAllConnections(); tlsServer.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('email records: SPF filtered from other TXT, DMARC found on the parent domain, MX sorted', async () => {
  const txt = {
    'shop.example.com': [['google-site-verification=abc'], ['v=spf1 include:_spf.google.com ', '~all']],
    '_dmarc.example.com': [['v=DMARC1; p=reject']],
  };
  const fake = {
    resolveTxt: async (n) => { if (txt[n]) return txt[n]; throw Object.assign(new Error('none'), { code: 'ENODATA' }); },
    resolveMx: async () => [{ exchange: 'ALT1.ASPMX.L.GOOGLE.COM', priority: 5 }, { exchange: 'aspmx.l.google.com', priority: 1 }],
  };
  const r = await emailRecords('shop.example.com', fake);
  assert.deepEqual(r, { ok: true, spf: ['v=spf1 include:_spf.google.com ~all'], dmarc: ['v=DMARC1; p=reject'], dmarcAt: 'example.com', mx: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'] });
  const broken = await emailRecords('x.example.com', { resolveTxt: async () => { throw Object.assign(new Error('x'), { code: 'ESERVFAIL' }); }, resolveMx: async () => [] });
  assert.deepEqual(broken, { ok: false, error: 'ESERVFAIL' });
});
