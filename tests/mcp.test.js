import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { handle, TOOL } from '../lib/mcp.js';
import { evaluate } from '../lib/checks.js';
import { site, STRONG, NOW } from './fixtures.js';

const report = { ok: true, ...evaluate(site({ headers: STRONG, dns: { dmarc: [] } }), { now: NOW }) };
const call = (method, params, id = 1) => handle({ jsonrpc: '2.0', id, method, params }, { scan: async (u) => (u === 'gone.example.com' ? { ok: false, status: 422, error: "That website didn't answer." } : report) });

test('initialize echoes a known protocol version and falls back for unknown ones', async () => {
  const r = await call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } });
  assert.equal(r.result.protocolVersion, '2025-06-18');
  assert.deepEqual(r.result.capabilities, { tools: {} });
  assert.equal(r.result.serverInfo.name, 'dare-check');
  assert.match((await call('initialize', { protocolVersion: '1999-01-01' })).result.protocolVersion, /^\d{4}-\d{2}-\d{2}$/);
});

test('lists one read-only tool with a real schema', async () => {
  const { result } = await call('tools/list');
  assert.deepEqual(result.tools, [TOOL]);
  assert.deepEqual(result.tools[0].inputSchema.required, ['url']);
  assert.equal(result.tools[0].annotations.readOnlyHint, true);
});

test('a call returns a human summary and the full report', async () => {
  const { result } = await call('tools/call', { name: 'check_website', arguments: { url: 'shop.example.com' } });
  assert.ok(!result.isError);
  assert.match(result.content[0].text, /shop\.example\.com: grade [A-F], \d+\/100/);
  assert.match(result.content[0].text, /Nothing stops scammers/);
  assert.equal(JSON.parse(result.content[1].text).host, 'shop.example.com');
});

test('tool failures come back as tool errors, protocol failures as protocol errors', async () => {
  const dead = await call('tools/call', { name: 'check_website', arguments: { url: 'gone.example.com' } });
  assert.equal(dead.result.isError, true);
  assert.match(dead.result.content[0].text, /didn't answer/);
  const missing = await call('tools/call', { name: 'check_website', arguments: {} });
  assert.equal(missing.result.isError, true);
  assert.equal((await call('tools/call', { name: 'nope' })).error.code, -32602);
  assert.equal((await call('no/such/method')).error.code, -32601);
  assert.equal((await handle({ jsonrpc: '2.0', id: 3 })).error.code, -32600);
});

test('notifications get no reply', async () => {
  assert.equal(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
});

test('the real server speaks line-delimited JSON-RPC over stdio, and the SSRF guard still applies', async () => {
  const child = spawn(process.execPath, [new URL('../bin/dare-check-mcp.js', import.meta.url).pathname], { stdio: ['pipe', 'pipe', 'pipe'] });
  const replies = [];
  let buf = '';
  child.stdout.on('data', (d) => { buf += d; let i; while ((i = buf.indexOf('\n')) >= 0) { replies.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  const send = (m) => child.stdin.write(JSON.stringify(m) + '\n');
  send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
  send({ jsonrpc: '2.0', method: 'notifications/initialized' });
  send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'check_website', arguments: { url: 'http://169.254.169.254/latest/meta-data/' } } });
  child.stdin.write('this is not json\n');
  child.stdin.end();
  await new Promise((r) => child.on('close', r));
  const by = Object.fromEntries(replies.filter((r) => r.id).map((r) => [r.id, r]));
  assert.equal(by[1].result.serverInfo.name, 'dare-check');
  assert.equal(by[2].result.tools[0].name, 'check_website');
  assert.equal(by[3].result.isError, true);
  assert.match(by[3].result.content[0].text, /domain name instead of an IP/);
  assert.ok(replies.some((r) => r.error?.code === -32700), 'bad JSON gets a parse error');
});
