/* Browser checks for the page. Needs the dev server: PORT=5190 node server.js
   node tests/ui.check.cjs [screenshot-dir] */
const { chromium } = require(process.env.HOME + '/.claude/scripts/node_modules/playwright');
const fs = require('fs');
const path = require('path');
const BASE = process.env.BASE || 'http://127.0.0.1:5190';
const SHOTS = process.argv[2];
const sample = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'public', 'sample.json'), 'utf8'));

let pass = 0, fail = 0;
const check = (name, ok, extra = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ' · ' + extra : ''}`); };

// a hostile report: every field a scanned site controls carries markup
const evil = JSON.parse(JSON.stringify(sample));
delete evil.sample;
evil.host = 'evil.example.com';
evil.checks[0].saw = '<img src=x onerror="window.__pwned=1">';
evil.checks[1].saw = '<script>window.__pwned=1</script>';
evil.fixes[0].code = '</code><img src=x onerror="window.__pwned=1">';

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const errors = [];
  // the 4xx from the mocked error test is logged by the browser on purpose; anything else counts
  page.on('console', (m) => { const t = m.text(); if ((m.type() === 'error' && !/status of 4\d\d/.test(t)) || /Content Security Policy/i.test(t)) errors.push(t); });
  page.on('pageerror', (e) => errors.push(String(e)));
  let dialog = false;
  page.on('dialog', (d) => { dialog = true; d.dismiss(); });

  await page.goto(BASE + '/');
  check('page loads with the hero title', await page.locator('h1').innerText().then((t) => /IS YOUR/i.test(t)));
  check('grade table lists 14 checks', (await page.locator('.methods tbody tr').count()) === 14);
  check('email link is assembled by script', /^mailto:jdare354@gmail\.com/.test(await page.locator('[data-email]').getAttribute('href')));
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, 'dc-desktop-hero.png') });

  // sample report
  await page.click('.bar-nav [data-sample]');
  await page.waitForSelector('.placard');
  check('sample report renders a C placard', (await page.locator('.placard .letter').innerText()) === sample.grade);
  check('sample shows its banner', await page.locator('.banner').isVisible());
  check('14 check rows in three groups', (await page.locator('.checks tbody tr').count()) === 14 && (await page.locator('.checks').count()) === 3);
  check('fixes listed in order', (await page.locator('.fix').count()) === sample.fixes.length && (await page.locator('.fix h3').first().innerText()).toLowerCase() === sample.fixes[0].title.toLowerCase());
  await page.locator('.fix .code-bar button').first().click();
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  check('copy button copies the fix code', clip === sample.fixes[0].code);
  check('status region announces the result', /Inspection complete/.test(await page.locator('#status').textContent()));
  if (SHOTS) { await page.screenshot({ path: path.join(SHOTS, 'dc-desktop-report.png'), fullPage: false }); await page.locator('#report').screenshot({ path: path.join(SHOTS, 'dc-desktop-report-full.png') }); }

  // hostile data stays text
  await page.route('**/api/scan', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(evil) }));
  await page.fill('#url', 'evil.example.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'evil.example.com');
  const pwned = await page.evaluate(() => window.__pwned === 1 || !!document.querySelector('#report img'));
  check('markup from a scanned site renders as text', !pwned && !dialog);
  check('it shows up as visible text', (await page.locator('.checks .saw').first().innerText()).includes('<img src=x'));
  check('share link written to the hash', page.url().endsWith('#check=evil.example.com'));

  // errors
  await page.route('**/api/scan', (route) => route.fulfill({ status: 422, contentType: 'application/json', body: JSON.stringify({ ok: false, error: "We couldn't find a website at that address. Check the spelling." }) }));
  await page.fill('#url', 'nope.example.com');
  await page.click('#scan button');
  await page.waitForSelector('.oops');
  check('error message shown in plain English', /couldn't find a website/.test(await page.locator('.oops h2').textContent()));
  await page.fill('#url', '');
  await page.click('#scan button');
  check('empty box asks for an address', /Type a website address/.test(await page.locator('.oops h2').textContent()));

  // shared link auto-runs (against the mock)
  await page.route('**/api/scan', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...evil, host: 'shared.example.com' }) }));
  await page.goto('about:blank');
  await page.goto(BASE + '/#check=shared.example.com');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'shared.example.com');
  check('a shared #check= link runs the scan on load', (await page.inputValue('#url')) === 'shared.example.com');
  await page.unroute('**/api/scan');

  // one real scan through the real API
  await page.goto(BASE + '/');
  await page.fill('#url', 'github.com');
  await page.press('#url', 'Enter');
  await page.waitForSelector('.placard', { timeout: 30000 });
  check('a real scan of github.com renders', /^[A-F]$/.test(await page.locator('.placard .letter').innerText()), await page.locator('.placard .score').innerText());

  // print view hides the chrome
  await page.emulateMedia({ media: 'print' });
  check('print view hides the header and form', !(await page.locator('.bar').isVisible()) && !(await page.locator('#scan').isVisible()) && (await page.locator('.placard').isVisible()));
  await page.emulateMedia({ media: 'screen' });
  check('no console or CSP errors on desktop', errors.length === 0, errors.slice(0, 3).join(' | '));

  // phone
  const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 3 });
  const p = await phone.newPage();
  const perr = [];
  p.on('pageerror', (e) => perr.push(String(e)));
  p.on('console', (m) => { if (m.type() === 'error') perr.push(m.text()); });
  await p.goto(BASE + '/');
  const wide = () => p.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  check('phone: no sideways scroll on the hero', (await wide()) <= 0, `${await wide()}px`);
  if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'dc-phone-hero.png') });
  await p.tap('.bar-nav [data-sample]');
  await p.waitForSelector('.placard');
  check('phone: no sideways scroll on the report', (await wide()) <= 0, `${await wide()}px`);
  const box = await p.locator('#scan button').boundingBox();
  check('phone: inspect button is a full-width 44px+ target', box.height >= 44 && box.width > 300, `${Math.round(box.width)}x${Math.round(box.height)}`);
  if (SHOTS) { await p.screenshot({ path: path.join(SHOTS, 'dc-phone-report.png') }); await p.locator('#report').screenshot({ path: path.join(SHOTS, 'dc-phone-report-full.png') }); }
  check('phone: no console errors', perr.length === 0, perr.slice(0, 2).join(' | '));

  // reduced motion: the loading bar stops sweeping
  const calm = await browser.newContext({ reducedMotion: 'reduce' });
  const c = await calm.newPage();
  await c.route('**/api/scan', () => { /* hold the request open */ });
  await c.goto(BASE + '/');
  await c.fill('#url', 'slow.example.com');
  await c.press('#url', 'Enter');
  await c.waitForSelector('.working .meter');
  const anim = await c.evaluate(() => getComputedStyle(document.querySelector('.working .meter'), '::after').animationName);
  check('reduced motion: loading bar does not animate', anim === 'none', anim);

  await browser.close();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
