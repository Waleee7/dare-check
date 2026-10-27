import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIP, normalizeTarget, guardedLookup, assertPublicUrl } from '../lib/guard.js';

test('private, loopback, link-local and metadata addresses are refused, public ones allowed', () => {
  const refused = ['10.0.0.1', '172.16.5.4', '172.31.255.255', '192.168.1.1', '127.0.0.1', '127.8.8.8', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '255.255.255.255', '198.18.0.1', '::', '::1', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '::ffff:7f00:1', '64:ff9b::7f00:1', '64:ff9b::a00:1', '2002:7f00:1::', '2001:db8::1', 'not-an-ip'];
  const allowed = ['8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1', '76.76.21.21', '2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8', '64:ff9b::808:808'];
  for (const ip of refused) assert.equal(isPublicIP(ip), false, ip);
  for (const ip of allowed) assert.equal(isPublicIP(ip), true, ip);
});

test('normalizeTarget keeps what people type and rejects anything that is not a public site', () => {
  assert.deepEqual(normalizeTarget('  Example.COM  '), { host: 'example.com', domain: 'example.com' });
  assert.deepEqual(normalizeTarget('https://www.joes-bakery.com/menu?x=1'), { host: 'www.joes-bakery.com', domain: 'joes-bakery.com' });
  assert.deepEqual(normalizeTarget('http://shop.example.co.uk'), { host: 'shop.example.co.uk', domain: 'shop.example.co.uk' });
  assert.equal(normalizeTarget('https://bücher.de').host, 'xn--bcher-kva.de');
  const bad = ['', 'localhost', 'http://localhost:3000', '127.0.0.1', 'http://[::1]/', 'http://169.254.169.254/latest/meta-data',
    'ftp://example.com', 'https://user:pw@example.com', 'example.com:8080', 'printer.local', 'db.internal', 'nas.lan', 'site.test',
    'javascript:alert(1)', 'example', 'x'.repeat(2100), 'exa mple.com', '-bad.com', 'http://2130706433/', 'http://0x7f.1/'];
  for (const s of bad) assert.throws(() => normalizeTarget(s), (e) => e.expose === true, JSON.stringify(s.slice(0, 40)));
});

test('guardedLookup refuses names that resolve to private addresses', async () => {
  const look = (host, opts) => new Promise((resolve) => guardedLookup(host, opts, (err, addr) => resolve({ err, addr })));
  const one = await look('localhost', {});
  assert.equal(one.err?.code, 'EBLOCKED');
  const all = await look('localhost', { all: true });
  assert.equal(all.err?.code, 'EBLOCKED');
});

test('assertPublicUrl blocks IP-literal redirects and odd ports', () => {
  assert.throws(() => assertPublicUrl(new URL('http://127.0.0.1/')), { code: 'EBLOCKED' });
  assert.throws(() => assertPublicUrl(new URL('http://[::ffff:10.0.0.1]/')), { code: 'EBLOCKED' });
  assert.throws(() => assertPublicUrl(new URL('https://example.com:8443/')), { code: 'EREDIRECT' });
  assert.throws(() => assertPublicUrl(new URL('file:///etc/passwd')), { code: 'EREDIRECT' });
  assert.doesNotThrow(() => assertPublicUrl(new URL('https://example.com/')));
  assert.doesNotThrow(() => assertPublicUrl(new URL('http://8.8.8.8/')));
});
