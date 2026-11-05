/* The terminal version of DARE CHECK. Everything it touches comes in through `io`, so tests can run
   it without a network or a real disk.

   dare-check example.com                    a readable report
   dare-check example.com --json             the raw report
   dare-check example.com --fail-under B     exit 1 if the grade is below B (for CI)
   dare-check --batch sites.txt --csv out.csv --md out.md    grade a list, worst first */
import fs from 'node:fs';
import { scanAddress } from './scan.js';
import { GROUPS } from './checks.js';

const ORDER = ['A', 'B', 'C', 'D', 'F'];
export const DEFAULT_BASE = 'https://dare-check.vercel.app';
const HELP = `DARE CHECK: a free safety grade for any website.

  dare-check <address>                 print a report
  dare-check <address> --json          print the report as JSON
  dare-check <address> --fail-under B  exit 1 if the grade is below B
  dare-check --batch <file>            grade a list of addresses, one per line
      --csv <out.csv>                  write the results as a spreadsheet
      --md <out.md>                    write the results as a Markdown table
      --base <url>                     where report links point (default ${DEFAULT_BASE})

Read-only: it loads each homepage the way a browser does and reads public records.
Only check sites you have a reason to look at, and go easy on the batch size.
`;

function parseArgs(argv) {
  const opts = { sites: [] };
  const needs = { '--fail-under': 'failUnder', '--batch': 'batch', '--csv': 'csv', '--md': 'md', '--base': 'base' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a in needs) {
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value.`);
      opts[needs[a]] = v;
    } else if (a.startsWith('-')) throw new Error(`Unknown option ${a}.`);
    else opts.sites.push(a);
  }
  if (opts.failUnder !== undefined) {
    opts.failUnder = opts.failUnder.toUpperCase();
    if (!ORDER.includes(opts.failUnder)) throw new Error('--fail-under takes A, B, C, D or F.');
  }
  return opts;
}

const palette = (on) => {
  const wrap = (code) => (s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  return { green: wrap('32'), red: wrap('31'), dim: wrap('2'), bold: wrap('1') };
};
const MARK = { pass: '[+]', warn: '[!]', fail: '[x]', skip: '[-]', info: '[i]' };

export function formatReport(r, color = false) {
  const c = palette(color);
  const paint = { pass: c.green, warn: (s) => s, fail: c.red, skip: c.dim, info: c.dim };
  const out = [];
  out.push(`${c.bold('DARE CHECK')}  ${r.host}`);
  out.push(`${c.bold(`Grade ${r.grade}`)}  ${r.score}/100  ·  ${[r.platform.name, r.builder?.name].filter(Boolean).join(' · ')}`, '');
  if (r.caveat) out.push(`[!] ${r.caveat}`, '');
  out.push(c.bold(r.summary.headline));
  for (const risk of r.summary.risks) out.push(`  ${paint[risk.status](MARK[risk.status])} ${risk.text}`);
  if (r.summary.good.length) out.push(`  ${c.green(MARK.pass)} Working: ${r.summary.good.join(', ')}.`);
  if (r.notes.length) { out.push(''); for (const n of r.notes) out.push(c.dim(`  ${n}`)); }
  for (const [id, label] of GROUPS) {
    out.push('', c.bold(label.toUpperCase()));
    for (const k of r.checks.filter((x) => x.group === id)) {
      out.push(`  ${paint[k.status](MARK[k.status])} ${k.title}`);
      out.push(c.dim(`      ${k.saw}`));
    }
  }
  if (r.fixes.length) {
    out.push('', c.bold('FIX THESE FIRST'));
    r.fixes.forEach((f, i) => {
      const pts = f.points ? `+${f.points} pts · ` : '';
      out.push(`  ${String(i + 1).padStart(2, '0')} ${c.bold(f.title)}`, c.dim(`     ${pts}${f.time} · ${f.who}`), `     ${f.text}`);
      if (f.code) { out.push(c.dim(`     ${f.file}:`)); for (const l of f.code.split('\n')) out.push(`       ${l}`); }
    });
    if (r.potential) out.push('', `Do all of that and this goes from ${r.grade} ${r.score} to ${r.potential.grade} ${r.potential.score}.`);
  }
  return out.join('\n') + '\n';
}

const cell = (v) => {
  let s = String(v ?? '');
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;   // keep spreadsheets from running a cell as a formula
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const mdCell = (v) => String(v ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export const reportLink = (base, host) => `${base.replace(/\/$/, '')}/#check=${encodeURIComponent(host)}&from=josh`;

/* A plain first line for a human to adapt: what's wrong and where to see it. Sending is up to them. */
function opener(row) {
  return `${row.topRisk} Free report for ${row.site}, nothing was changed on your site: ${row.link}`;
}

export function toRows(results, base) {
  return results.map(({ site, report: r }) => {
    if (!r.ok) return { site, grade: '', score: '', fails: '', warns: '', hosting: '', builtWith: '', topRisk: '', fastestFix: '', link: '', opener: '', caveat: '', error: r.error };
    const row = {
      site: r.host, grade: r.grade, score: r.score, fails: r.counts.fail, warns: r.counts.warn, hosting: r.platform.name, builtWith: r.builder?.name ?? '',
      topRisk: r.summary.risks[0]?.text ?? r.summary.headline, fastestFix: r.summary.next ? `${r.summary.next.title} (${r.summary.next.time})` : '', link: reportLink(base, r.host), caveat: r.caveat ?? '', error: '',
    };
    return { ...row, opener: opener(row) };
  }).sort((a, b) => (a.score === '' ? 1 : b.score === '' ? -1 : a.score - b.score));
}

const COLUMNS = ['site', 'grade', 'score', 'fails', 'warns', 'hosting', 'builtWith', 'topRisk', 'fastestFix', 'link', 'opener', 'caveat', 'error'];
export const toCsv = (rows) => [COLUMNS.join(','), ...rows.map((r) => COLUMNS.map((k) => cell(r[k])).join(','))].join('\n') + '\n';
export const toMarkdown = (rows) => ['| Site | Grade | Score | Top risk | Fastest fix | Report |', '|---|---|---|---|---|---|',
  ...rows.map((r) => `| ${mdCell(r.site)} | ${r.grade || '—'} | ${r.score === '' ? '—' : r.score} | ${mdCell(r.topRisk || r.error)} | ${mdCell(r.fastestFix)} | ${r.link ? `[open](${r.link})` : '—'} |`)].join('\n') + '\n';

async function runBatch(opts, io) {
  let lines;
  try {
    lines = io.readFile(opts.batch).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  } catch {
    io.err(`Couldn't read ${opts.batch}.\n`);
    return 2;
  }
  const sites = [...new Set(lines)];
  if (!sites.length) { io.err('That file has no addresses in it.\n'); return 2; }
  const results = [];
  let next = 0;
  // two at a time, so a long list stays gentle on everyone involved
  await Promise.all(Array.from({ length: Math.min(2, sites.length) }, async () => {
    while (next < sites.length) {
      const site = sites[next++];
      const report = await io.scan(site);
      results.push({ site, report });
      io.err(`${String(results.length).padStart(3)}/${sites.length}  ${report.ok ? `${report.grade} ${String(report.score).padStart(3)}` : ' --  '}  ${site}\n`);
    }
  }));
  const rows = toRows(results, opts.base ?? DEFAULT_BASE);
  if (opts.csv) io.writeFile(opts.csv, toCsv(rows));
  if (opts.md) io.writeFile(opts.md, toMarkdown(rows));
  if (opts.json) io.out(JSON.stringify(rows, null, 2) + '\n');
  else if (!opts.csv && !opts.md) io.out(toMarkdown(rows));
  const ok = rows.filter((r) => r.grade);
  io.err(`\n${ok.length} graded, ${rows.length - ok.length} couldn't be checked.${opts.csv ? ` Wrote ${opts.csv}.` : ''}${opts.md ? ` Wrote ${opts.md}.` : ''}\n`);
  return 0;
}

export async function main(argv, partial = {}) {
  const io = {
    scan: (s) => scanAddress(s),
    out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s),
    readFile: (p) => fs.readFileSync(p, 'utf8'), writeFile: (p, d) => fs.writeFileSync(p, d), appendFile: (p, d) => fs.appendFileSync(p, d),
    env: process.env, color: Boolean(process.stdout.isTTY) && !process.env.NO_COLOR, ...partial,
  };
  let opts;
  try { opts = parseArgs(argv); } catch (e) { io.err(`${e.message}\n\n${HELP}`); return 2; }
  if (opts.help) { io.out(HELP); return 0; }
  if (opts.batch) return runBatch(opts, io);
  if (opts.sites.length !== 1) { io.err(HELP); return 2; }

  const r = await io.scan(opts.sites[0]);
  if (!r.ok) { io.err(`${r.error}\n`); return 2; }
  io.out(opts.json ? JSON.stringify(r, null, 2) + '\n' : formatReport(r, io.color));

  // inside GitHub Actions: expose the grade and write a job summary
  if (io.env.GITHUB_OUTPUT) io.appendFile(io.env.GITHUB_OUTPUT, `grade=${r.grade}\nscore=${r.score}\n`);
  if (io.env.GITHUB_STEP_SUMMARY) {
    const risks = r.summary.risks.map((x) => `- ${x.text}`).join('\n');
    io.appendFile(io.env.GITHUB_STEP_SUMMARY, `### DARE CHECK: ${r.host} gets ${r.grade} (${r.score}/100)\n\n${r.summary.headline}\n\n${risks}\n`);
  }
  if (opts.failUnder && ORDER.indexOf(r.grade) > ORDER.indexOf(opts.failUnder)) {
    io.err(`\n${r.host} got ${r.grade}, below the required ${opts.failUnder}.\n`);
    return 1;
  }
  return 0;
}
