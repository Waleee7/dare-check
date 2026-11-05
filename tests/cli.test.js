import { test } from 'node:test';
import assert from 'node:assert/strict';
import { main, formatReport, toCsv, toMarkdown, toRows, reportLink, DEFAULT_BASE } from '../lib/cli.js';
import { evaluate } from '../lib/checks.js';
import { site, STRONG, NOW } from './fixtures.js';

const report = (o = {}) => ({ ok: true, ...evaluate(site({ headers: STRONG, ...o }), { now: NOW }) });
const weak = (host = 'weak.example.com') => report({ host, headers: {}, dns: { spf: [], dmarc: [] } });

function harness(scan, files = {}) {
  const log = { out: '', err: '', files: {}, appended: {} };
  const io = {
    scan, out: (s) => { log.out += s; }, err: (s) => { log.err += s; },
    readFile: (p) => { if (p in files) return files[p]; throw new Error('missing'); },
    writeFile: (p, d) => { log.files[p] = d; }, appendFile: (p, d) => { log.appended[p] = (log.appended[p] ?? '') + d; },
    env: {}, color: false,
  };
  return { io, log };
}

test('prints a readable report and exits 0', async () => {
  const { io, log } = harness(async () => weak());
  assert.equal(await main(['weak.example.com'], io), 0);
  assert.match(log.out, /DARE CHECK {2}weak\.example\.com/);
  assert.match(log.out, /Nothing stops scammers/);
  assert.match(log.out, /FIX THESE FIRST/);
  assert.match(log.out, /v=DMARC1; p=quarantine/);
  assert.doesNotMatch(log.out, /\x1b\[/, 'no color codes when not asked for');
});

test('--json prints the report, --fail-under sets the exit code', async () => {
  const a = harness(async () => weak());
  assert.equal(await main(['weak.example.com', '--json'], a.io), 0);
  assert.equal(JSON.parse(a.log.out).host, 'weak.example.com');
  const low = harness(async () => weak());
  assert.equal(await main(['weak.example.com', '--fail-under', 'b'], low.io), 1);
  assert.match(low.log.err, /below the required B/);
  const good = harness(async () => report());
  assert.equal(await main(['x.example.com', '--fail-under', 'A'], good.io), 0);
  const edge = harness(async () => report());
  assert.equal(await main(['x.example.com', '--fail-under', 'F'], edge.io), 0, 'F as the bar never fails');
});

test('bad usage and unreachable sites exit 2 with a plain message', async () => {
  const t = async (args, scan = async () => report()) => { const h = harness(scan); return [await main(args, h.io), h.log.err]; };
  assert.equal((await t([]))[0], 2);
  assert.equal((await t(['a.com', 'b.com']))[0], 2);
  const [code, err] = await t(['a.com', '--fail-under', 'Z']);
  assert.equal(code, 2);
  assert.match(err, /takes A, B, C, D or F/);
  assert.equal((await t(['--nope']))[0], 2);
  assert.equal((await t(['a.com', '--fail-under']))[0], 2);
  const [dead, msg] = await t(['gone.example.com'], async () => ({ ok: false, status: 422, error: "That website didn't answer." }));
  assert.equal(dead, 2);
  assert.match(msg, /didn't answer/);
  const help = harness(async () => report());
  assert.equal(await main(['--help'], help.io), 0);
  assert.match(help.log.out, /--batch/);
});

test('inside GitHub Actions it exposes the grade and writes a job summary', async () => {
  const { io, log } = harness(async () => weak());
  io.env = { GITHUB_OUTPUT: '/out', GITHUB_STEP_SUMMARY: '/sum' };
  await main(['weak.example.com'], io);
  assert.match(log.appended['/out'], /^grade=[A-F]\nscore=\d+\n$/);
  assert.match(log.appended['/sum'], /### DARE CHECK: weak\.example\.com gets/);
});

test('--batch grades a list worst first, tolerates failures, and writes CSV and Markdown', async () => {
  const seen = [];
  const scan = async (s) => {
    seen.push(s);
    if (s === 'gone.example.com') return { ok: false, status: 422, error: "That website didn't answer." };
    return s === 'strong.example.com' ? report({ host: s }) : weak(s);
  };
  const { io, log } = harness(scan, { 'sites.txt': '# my list\nstrong.example.com\n\nweak.example.com\ngone.example.com\nweak.example.com\n' });
  assert.equal(await main(['--batch', 'sites.txt', '--csv', 'o.csv', '--md', 'o.md', '--base', 'https://dc.test/'], io), 0);
  assert.deepEqual([...seen].sort(), ['gone.example.com', 'strong.example.com', 'weak.example.com'], 'comments, blanks and repeats are dropped');
  const csv = log.files['o.csv'].trim().split('\n');
  assert.match(csv[0], /^site,grade,score,fails,warns,hosting,builtWith,topRisk,fastestFix,link,opener,caveat,error$/);
  assert.equal(csv.length, 4);
  assert.match(csv[1], /^weak\.example\.com,/, 'worst first');
  assert.match(csv[3], /^gone\.example\.com,.*didn't answer/, 'failures last, with the reason');
  assert.match(csv[1], /https:\/\/dc\.test\/#check=weak\.example\.com&from=josh/);
  assert.match(log.files['o.md'], /\| weak\.example\.com \|/);
  assert.match(log.err, /2 graded, 1 couldn't be checked/);
});

test('--batch with a missing or empty file exits 2', async () => {
  const none = harness(async () => report());
  assert.equal(await main(['--batch', 'nope.txt'], none.io), 2);
  assert.match(none.log.err, /Couldn't read nope\.txt/);
  const empty = harness(async () => report(), { 'e.txt': '# nothing\n\n' });
  assert.equal(await main(['--batch', 'e.txt'], empty.io), 2);
});

test('CSV cells are quoted, and formulas are defused', () => {
  const csv = toCsv([{ site: '=cmd()', grade: 'F', topRisk: 'has, comma and "quotes"', opener: '+1 line\nbreak' }]);
  assert.match(csv, /^site,/);
  assert.match(csv, /'=cmd\(\),F/);
  assert.match(csv, /"has, comma and ""quotes"""/);
  assert.match(csv, /"'\+1 line\nbreak"/);
});

test('rows carry an opener a person can adapt, and markdown stays one row per site', () => {
  const [row] = toRows([{ site: 'weak.example.com', report: weak() }], DEFAULT_BASE);
  assert.match(row.opener, /Nothing stops scammers|no working secure|Security filters/);
  assert.match(row.opener, /nothing was changed on your site/);
  assert.equal(row.link, reportLink(DEFAULT_BASE, 'weak.example.com'));
  const md = toMarkdown([{ site: 'a|b', grade: 'C', score: 70, topRisk: 'x\ny', fastestFix: '', link: '' }]);
  assert.match(md, /a\\\|b/);
  assert.equal(md.trim().split('\n').length, 3);
});

test('a rough grade says so in the terminal', () => {
  assert.match(formatReport(report({ https: { status: 429 } }), false), /\[!\] Your site turned us away/);
});

test('color only when asked', () => {
  assert.match(formatReport(weak(), true), /\x1b\[/);
  assert.doesNotMatch(formatReport(weak(), false), /\x1b\[/);
});
