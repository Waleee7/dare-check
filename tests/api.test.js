import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import handler, { _test } from '../api/scan.js';

const server = http.createServer(handler);
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/api/scan`;
after(() => server.close());

const post = (body, ip = '203.0.113.9') => fetch(base, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body });

test('only POST is accepted', async () => {
  const r = await fetch(base);
  assert.equal(r.status, 405);
  assert.equal(r.headers.get('allow'), 'POST');
});

test('bad input gets a plain-English 400 and never reaches the network', async () => {
  const cases = [['not json', /website address/], [JSON.stringify({ url: 'localhost' }), /public website/], [JSON.stringify({ url: '10.0.0.1' }), /domain name instead/], [JSON.stringify({ url: 'nas.local' }), /private network/], ['x'.repeat(5000), /website address/]];
  for (const [body, msg] of cases) {
    const r = await post(body, '203.0.113.10');
    assert.equal(r.status, 400, body.slice(0, 30));
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.match((await r.json()).error, msg);
  }
});

test('each visitor gets 8 checks a minute, then a 429 with Retry-After', async () => {
  _test.hits.clear();
  const codes = [];
  for (let i = 0; i < 9; i++) codes.push((await post(JSON.stringify({ url: 'localhost' }), '203.0.113.77')).status);
  assert.deepEqual(codes, [400, 400, 400, 400, 400, 400, 400, 400, 429]);
  const r = await post('{}', '203.0.113.77');
  assert.equal(r.headers.get('retry-after'), '60');
  assert.equal((await post('{}', '203.0.113.78')).status, 400, 'other visitors are unaffected');
});
