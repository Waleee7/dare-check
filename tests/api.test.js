import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import handler, { _test, createHandler } from '../api/scan.js';
import { createBadge, badgeSvg } from '../api/badge.js';
import { site, STRONG } from './fixtures.js';

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

/* ---------------- content type, streaming, freshness ---------------- */

async function listen(fn) {
  const srv = http.createServer(fn);
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close() };
}
const STUB_STEPS = ['https', 'cert', 'http', 'www', 'email', 'dkim', 'blocklist', 'domain', 'software'];
const stubRun = (calls = []) => async (target, { onStep } = {}) => {
  calls.push(target.host);
  for (const id of STUB_STEPS) onStep?.({ id, note: `${id} done` });
  return site({ host: target.host, headers: STRONG });
};

test('non-JSON bodies are refused, so another site can\'t drive the API with a plain form post', async () => {
  const r = await fetch(base, { method: 'POST', headers: { 'content-type': 'text/plain', 'x-forwarded-for': '203.0.113.20' }, body: JSON.stringify({ url: 'example.com' }) });
  assert.equal(r.status, 415);
});

test('asked for a stream, each step arrives as its own line, ending in the report', async () => {
  _test.cache.clear();
  const srv = await listen(createHandler({ run: stubRun() }));
  try {
    const r = await fetch(srv.url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/x-ndjson', 'x-forwarded-for': '203.0.113.30' }, body: JSON.stringify({ url: 'stream.example.com' }) });
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /ndjson/);
    assert.equal(r.headers.get('cache-control'), 'no-store, no-transform');
    const lines = (await r.text()).trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(lines.slice(0, -1).map((l) => l.id), STUB_STEPS);
    assert.ok(lines.slice(0, -1).every((l) => l.type === 'step' && l.note));
    const last = lines.at(-1);
    assert.equal(last.type, 'report');
    assert.equal(last.report.host, 'stream.example.com');
    assert.equal(last.report.grade, 'A');
  } finally { srv.close(); }
});

test('a site that cannot be reached ends the stream with a plain-English error', async () => {
  _test.cache.clear();
  const dead = async () => ({ https: { ok: false, error: 'ENOTFOUND' }, http: { ok: false, error: 'ENOTFOUND' } });
  const srv = await listen(createHandler({ run: dead }));
  try {
    const r = await fetch(srv.url, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/x-ndjson', 'x-forwarded-for': '203.0.113.31' }, body: JSON.stringify({ url: 'gone.example.com' }) });
    const lines = (await r.text()).trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(lines, [{ type: 'error', error: "We couldn't find a website at that address. Check the spelling." }]);
    const j = await fetch(srv.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.32' }, body: JSON.stringify({ url: 'gone.example.com' }) });
    assert.equal(j.status, 422, 'without the stream it stays a normal status code');
  } finally { srv.close(); }
});

test('results are cached for two minutes per site, and "fresh" re-checks for real', async () => {
  _test.cache.clear();
  const calls = [];
  const srv = await listen(createHandler({ run: stubRun(calls) }));
  const ask = (body, ip) => fetch(srv.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify(body) });
  try {
    assert.equal((await (await ask({ url: 'cache.example.com' }, '203.0.113.40')).json()).host, 'cache.example.com');
    await ask({ url: 'cache.example.com' }, '203.0.113.41');
    assert.equal(calls.length, 1, 'second visitor gets the cached copy');
    await ask({ url: 'cache.example.com', fresh: true }, '203.0.113.42');
    assert.equal(calls.length, 2, 'fresh skips the cache');
    await ask({ url: 'cache.example.com', fresh: 'yes' }, '203.0.113.43');
    assert.equal(calls.length, 2, 'only a real true counts');
  } finally { srv.close(); }
});

test('the scanner blowing up gives a friendly 502 and leaks nothing', async () => {
  _test.cache.clear();
  const srv = await listen(createHandler({ run: async () => { throw new Error('secret internal detail'); } }));
  try {
    const r = await fetch(srv.url, { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '203.0.113.50' }, body: JSON.stringify({ url: 'boom.example.com' }) });
    assert.equal(r.status, 502);
    const text = await r.text();
    assert.match(text, /Something went wrong/);
    assert.doesNotMatch(text, /secret/);
  } finally { srv.close(); }
});

/* ---------------- badge ---------------- */

test('badge: a real grade, cacheable, embeddable from other sites', async () => {
  _test.cache.clear();
  const srv = await listen(createBadge({ run: stubRun() }));
  try {
    const r = await fetch(`${srv.url}/api/badge?host=badge.example.com`, { headers: { 'x-forwarded-for': '203.0.113.60' } });
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /image\/svg\+xml/);
    assert.match(r.headers.get('cache-control'), /s-maxage=86400/);
    assert.equal(r.headers.get('cross-origin-resource-policy'), 'cross-origin');
    const svg = await r.text();
    assert.match(svg, /aria-label="DARE CHECK grade A"/);
    assert.match(svg, />A<\/text>/);
  } finally { srv.close(); }
});

test('badge: bad hosts and blown limits get a harmless "?" and script can never get in', async () => {
  const srv = await listen(createBadge({ run: stubRun() }));
  try {
    const bad = await fetch(`${srv.url}/api/badge?host=${encodeURIComponent('<script>alert(1)</script>')}`, { headers: { 'x-forwarded-for': '203.0.113.61' } });
    const svg = await bad.text();
    assert.match(svg, />\?<\/text>/);
    assert.doesNotMatch(svg, /script|alert/);
    assert.match((await fetch(`${srv.url}/api/badge`, { headers: { 'x-forwarded-for': '203.0.113.61' } }).then((x) => x.text())), />\?<\/text>/);
    let last;
    for (let i = 0; i < 9; i++) last = await fetch(`${srv.url}/api/badge?host=localhost`, { headers: { 'x-forwarded-for': '203.0.113.62' } });
    assert.equal(last.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(`${srv.url}/api/badge`, { method: 'POST' })).status, 405);
  } finally { srv.close(); }
});

test('badge colors: only an A or B earns the green', () => {
  assert.match(badgeSvg('A'), /fill="#00ff66"/);
  assert.match(badgeSvg('B'), /fill="#00ff66"/);
  for (const g of ['C', 'D', 'F', '?']) assert.doesNotMatch(badgeSvg(g), /fill="#00ff66"/, g);
  assert.match(badgeSvg('<x>'), />\?<\/text>/, 'anything but a grade letter shows as ?');
});
