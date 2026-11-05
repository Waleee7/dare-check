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
const json = (body, status = 200) => (route) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
const live = (host, extra = {}) => { const r = JSON.parse(JSON.stringify(sample)); delete r.sample; return { ...r, host, domain: host, ...extra }; };

// a hostile report: every field a scanned site controls carries markup
const evil = live('evil.example.com');
const XSS = '<img src=x onerror="window.__pwned=1">';
evil.checks[0].saw = XSS;
evil.checks[1].saw = '<script>window.__pwned=1</script>';
evil.fixes[0].code = '</code>' + XSS;
evil.fixes[0].file = XSS;
evil.notes = [XSS];
evil.caveat = XSS;
evil.platform.name = XSS;
evil.registrar = XSS;
evil.builder = { id: 'x', name: XSS };
evil.spoof = { domain: XSS };
evil.summary.headline = XSS;
evil.summary.risks = [{ id: 'dmarc', status: 'fail', text: XSS }];
evil.summary.next = { title: XSS, points: 1, time: XSS, who: XSS };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, permissions: ['clipboard-read', 'clipboard-write'], acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  // the 4xx from the mocked error test is logged by the browser on purpose; anything else counts
  page.on('console', (m) => { const t = m.text(); if ((m.type() === 'error' && !/status of 4\d\d/.test(t)) || /Content Security Policy/i.test(t)) errors.push(t); });
  page.on('pageerror', (e) => errors.push(String(e)));
  let dialog = false;
  page.on('dialog', (d) => { dialog = true; d.dismiss(); });
  const clipboard = () => page.evaluate(() => navigator.clipboard.readText());

  await page.goto(BASE + '/');
  check('page loads with the hero title', await page.locator('h1').innerText().then((t) => /IS YOUR/i.test(t)));
  check('grade table lists 20 scored checks plus 2 reported ones', (await page.locator('.methods tbody tr').count()) === 22 && (await page.locator('.methods tbody tr[data-check]').count()) === 20);
  check('email link is assembled by script', /^mailto:jdare354@gmail\.com/.test(await page.locator('[data-email]').getAttribute('href')));
  check('no recent-checks list on a first visit', await page.locator('[data-recent]').isHidden());
  if (SHOTS) await page.screenshot({ path: path.join(SHOTS, 'desktop-hero.png') });
  await page.locator('.faq summary').first().click();
  check('FAQ answers open', await page.locator('.faq details p').first().isVisible());
  await page.locator('.dev [data-copy]').first().click();
  check('developer snippets copy', (await clipboard()).includes('npx github:Waleee7/dare-check'));
  if (SHOTS) {
    await page.locator('#faq').screenshot({ path: path.join(SHOTS, 'desktop-faq.png') });
    await page.locator('#dev').screenshot({ path: path.join(SHOTS, 'desktop-dev.png') });
  }

  // sample report
  await page.click('.bar-nav [data-sample]');
  await page.waitForSelector('.placard');
  check('sample report renders its grade', (await page.locator('.head .placard .letter').innerText()) === sample.grade);
  check('sample shows its banner', await page.locator('.banner').isVisible());
  check('22 check rows in four groups', (await page.locator('.checks tbody tr').count()) === 22 && (await page.locator('.checks').count()) === 4);
  check('fixes listed in order', (await page.locator('.fix').count()) === sample.fixes.length && (await page.locator('.fix h3').first().innerText()).toLowerCase() === sample.fixes[0].title.toLowerCase());
  check('each fix says how long and who', (await page.locator('.fix-meta').count()) === sample.fixes.length && /about 5 minutes · you, at your domain registrar/i.test(await page.locator('.fix-meta').first().innerText()));
  check('no caveat on a clean read', (await page.locator('.caveat').count()) === 0);
  check('the short version leads with a headline and risks', (await page.locator('.short-head').innerText()) === sample.summary.headline && (await page.locator('.short-risks li').count()) === sample.summary.risks.length);
  check('the short version promises the score that fixes add up to', (await page.locator('.short-next').innerText()).includes(`${sample.grade} ${sample.score} becomes ${sample.potential.grade} ${sample.potential.score}`));
  check('the spoof illustration shows the real domain', (await page.locator('.mail').innerText()).includes('billing@joesbakery.example') && /no email was sent/i.test(await page.locator('.spoof').innerText()));
  await page.locator('.short-jump button').click();
  await page.waitForTimeout(100);
  check('the short version jumps to the fixes', await page.evaluate(() => { const t = document.querySelector('[data-fixes]').getBoundingClientRect().top; return t >= -5 && t < 120; }));
  check('no compare or web-person buttons on a sample', (await page.locator('[data-compare]').count()) === 0 && (await page.locator('.fix-actions').count()) === 0);
  await page.locator('.fix .code-bar button').first().click();
  check('copy button copies the fix code', (await clipboard()) === sample.fixes[0].code);
  check('status region announces the result', /Inspection complete/.test(await page.locator('#status').textContent()));
  if (SHOTS) { await page.screenshot({ path: path.join(SHOTS, 'desktop-report.png') }); await page.locator('#report').screenshot({ path: path.join(SHOTS, 'desktop-report-full.png') }); }

  // hostile data stays text
  await page.route('**/api/scan', json(evil));
  await page.fill('#url', 'evil.example.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'evil.example.com');
  const pwned = await page.evaluate(() => window.__pwned === 1 || !!document.querySelector('#report img'));
  check('markup from a scanned site renders as text in every field', !pwned && !dialog);
  check('it shows up as visible text', (await page.locator('.checks .saw').first().innerText()).includes('<img src=x'));
  check('share link written to the hash', page.url().endsWith('#check=evil.example.com'));

  // a rough grade is labeled, at the top
  await page.route('**/api/scan', json(live('blocked.example.com', { caveat: 'Your site turned us away (status 429), so we graded the page it sent instead of your homepage.' })));
  await page.fill('#url', 'blocked.example.com');
  await page.press('#url', 'Enter');
  await page.waitForSelector('.caveat');
  check('a rough grade is labeled above the summary', /turned us away/.test(await page.locator('.caveat').innerText()) && await page.evaluate(() => document.querySelector('.caveat').compareDocumentPosition(document.querySelector('.short')) === Node.DOCUMENT_POSITION_FOLLOWING));
  await page.unroute('**/api/scan');

  // errors
  await page.route('**/api/scan', json({ ok: false, error: "We couldn't find a website at that address. Check the spelling." }, 422));
  await page.fill('#url', 'nope.example.com');
  await page.click('#scan button[type="submit"]');
  await page.waitForSelector('.oops');
  check('error message shown in plain English', /couldn't find a website/.test(await page.locator('.oops h2').textContent()));
  await page.fill('#url', '');
  await page.click('#scan button[type="submit"]');
  check('empty box asks for an address', /Type a website address/.test(await page.locator('.oops h2').textContent()));

  // shared link auto-runs (against the mock), including the note from Josh
  await page.route('**/api/scan', json(live('shared.example.com')));
  await page.goto('about:blank');
  await page.goto(BASE + '/#check=shared.example.com&from=josh');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'shared.example.com');
  check('a shared #check= link runs the scan on load', (await page.inputValue('#url')) === 'shared.example.com');
  check('a link from Josh says who ran it and that nothing changed', /Josh Dare ran this for you.*nothing on your site was changed/i.test(await page.locator('.banner').innerText()));
  check('that note survives in the link', page.url().includes('from=josh'));
  await page.unroute('**/api/scan');
  await page.route('**/api/scan', json(live('someone-else.example.com')));
  await page.fill('#url', 'someone-else.example.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'someone-else.example.com');
  check('checking a different site drops the note from Josh', (await page.locator('.banner').count()) === 0 && !page.url().includes('from=josh'));
  await page.goto('about:blank');
  await page.goto(BASE + '/#check=%E0%A4%A');
  await page.waitForTimeout(200);
  check('a malformed link does not crash the page', errors.length === 0, errors.slice(0, 2).join(' | '));
  await page.unroute('**/api/scan');

  // this browser's memory, and the change since last time
  await page.evaluate(() => localStorage.clear());
  await page.route('**/api/scan', json(live('memory.example.com', { score: 60, grade: 'D', fetchedAt: '2026-11-01T10:00:00.000Z' })));
  await page.goto('about:blank');
  await page.goto(BASE + '/');
  await page.fill('#url', 'memory.example.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'memory.example.com');
  check('a first check shows no "since last check" line', (await page.locator('.short-delta').count()) === 0);
  check('recent checks appear', /memory\.example\.com/.test(await page.locator('[data-recent]').innerText()));
  let fresh = null;
  await page.unroute('**/api/scan');
  await page.route('**/api/scan', async (route) => { fresh = JSON.parse(route.request().postData()).fresh; return json(live('memory.example.com', { score: 85, grade: 'B', fetchedAt: '2026-11-02T10:00:00.000Z' }))(route); });
  await page.click('[data-recheck]');
  await page.waitForSelector('.short-delta');
  check('check again asks for a fresh scan', fresh === true);
  check('a re-check shows what changed', /up 25 points, from D 60/.test(await page.locator('.short-delta').innerText()));
  await page.locator('[data-recent] .link--dim').click();
  check('recent checks can be cleared', await page.locator('[data-recent]').isHidden() && (await page.evaluate(() => localStorage.getItem('dc-history'))) === null);
  await page.unroute('**/api/scan');

  // fix tools
  const fixHost = 'fixes.example.com';
  await page.route('**/api/scan', json(live(fixHost, { dates: { domain: '2028-03-01T00:00:00.000Z', cert: '2027-01-01T00:00:00.000Z', certIssuer: 'Sectigo Limited' } })));
  await page.goto('about:blank');
  await page.goto(BASE + '/');
  await page.fill('#url', fixHost);
  await page.press('#url', 'Enter');
  await page.waitForSelector('.fix-actions');
  const mail = decodeURIComponent(await page.locator('.fix-actions a').getAttribute('href'));
  check('"send to my web person" writes a mail with the fixes and the link', mail.startsWith('mailto:?') && mail.includes(`Website safety fixes for ${fixHost}`) && mail.includes(sample.fixes[0].title) && mail.includes(`#check=${fixHost}`));
  check('...short enough for every mail app', mail.length < 2000, `${mail.length} chars`);
  await page.locator('.fix-actions button').click();
  const all = await clipboard();
  check('"copy all fixes" includes the code', all.includes(sample.fixes[0].code) && all.includes(fixHost));
  check('the email to Josh names the top fixes', decodeURIComponent(await page.locator('.cta a').getAttribute('href')).includes(sample.fixes[0].title));
  const rows = page.locator('.dates li');
  check('dates to remember: the domain and a paid certificate', (await rows.count()) === 2);
  const [dl] = await Promise.all([page.waitForEvent('download'), rows.first().locator('button').click()]);
  const ics = fs.readFileSync(await dl.path(), 'utf8');
  check('the reminder is a real calendar file, 30 days early', dl.suggestedFilename() === `domain-reminder-${fixHost}.ics` && ics.includes('BEGIN:VEVENT') && ics.includes('DTSTART;VALUE=DATE:20280131') && ics.includes('\r\n'));
  if (SHOTS) await page.locator('.dates').screenshot({ path: path.join(SHOTS, 'desktop-dates.png') });
  await page.unroute('**/api/scan');
  await page.route('**/api/scan', json(live('auto.example.com', { dates: { domain: null, cert: '2027-01-01T00:00:00.000Z', certIssuer: "Let's Encrypt" } })));
  await page.fill('#url', 'auto.example.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'auto.example.com');
  check('no reminder for certificates that renew themselves', (await page.locator('.dates').count()) === 0);
  await page.unroute('**/api/scan');

  // badge offer only on a good grade
  await page.route('**/api/scan', json(live('good.example.com', { grade: 'A', score: 96, fixes: [], spoof: null, potential: null, summary: { ...sample.summary, headline: 'The basics are covered.', risks: [], good: ['secure connection'], next: null, potential: null } })));
  await page.route('**/api/badge**', (route) => route.fulfill({ status: 200, contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="132" height="32"/>' }));
  await page.fill('#url', 'good.example.com');
  await page.press('#url', 'Enter');
  await page.waitForSelector('.badge-box');
  check('an A earns a badge to embed', (await page.locator('.badge-box code').innerText()).includes('/api/badge?host=good.example.com'));
  check('no fixes means no fix list and no spoof card', (await page.locator('.fix').count()) === 0 && (await page.locator('.spoof').count()) === 0);
  await page.unroute('**/api/scan');
  await page.unroute('**/api/badge**');
  check('a C earns no badge', await (async () => { await page.route('**/api/scan', json(live('so-so.example.com'))); await page.fill('#url', 'so-so.example.com'); await page.press('#url', 'Enter'); await page.waitForFunction(() => document.querySelector('.facts dd')?.textContent === 'so-so.example.com'); await page.unroute('**/api/scan'); return (await page.locator('.badge-box').count()) === 0; })());

  // compare with a competitor
  await page.route('**/api/scan', async (route) => {
    const u = JSON.parse(route.request().postData()).url;
    if (u.includes('nobody')) return json({ ok: false, error: "That website didn't answer." }, 422)(route);
    const r = live(u.includes('rival') ? 'rival.example.com' : 'me.example.com', u.includes('rival') ? { grade: 'B', score: 88 } : {});
    if (u.includes('rival')) r.checks.find((c) => c.id === 'dmarc').status = 'pass';
    return json(r)(route);
  });
  await page.goto('about:blank');
  await page.goto(BASE + '/');
  await page.fill('#url', 'me.example.com');
  await page.press('#url', 'Enter');
  await page.waitForSelector('[data-compare]');
  await page.click('[data-compare]');
  check('compare opens a box with focus in it', await page.evaluate(() => document.activeElement?.id === 'rival'));
  await page.fill('#rival', 'nobody.example.com');
  await page.press('#rival', 'Enter');
  await page.waitForSelector('.oops--small');
  check('a competitor that fails stays out of your report', /didn't answer/.test(await page.locator('.oops--small').innerText()) && (await page.locator('.head .placard').count()) === 1);
  await page.click('[data-compare]');
  await page.click('[data-compare]');
  await page.fill('#rival', 'rival.example.com');
  await page.press('#rival', 'Enter');
  await page.waitForSelector('.versus');
  check('compare shows both grades side by side', (await page.locator('.versus .placard').count()) === 2 && (await page.locator('.versus .placard .letter').nth(1).innerText()) === 'B');
  check('compare says who is ahead', /rival\.example\.com is ahead by 18 points/.test(await page.locator('.versus-say').innerText()));
  check('only the differences show up front', (await page.locator('.versus > .table-wrap tbody tr').count()) === 1 && (await page.locator('.vs-table tbody tr').first().getAttribute('data-gap')) === 'behind');
  check('the even checks are tucked away', /19 more checks with no winner/i.test(await page.locator('.vs-even summary').innerText()) && !(await page.locator('.vs-even table').isVisible()));
  check('compare is shareable', page.url().includes('&vs=rival.example.com'));
  if (SHOTS) await page.locator('.compare-slot').screenshot({ path: path.join(SHOTS, 'desktop-compare.png') });
  await page.goto('about:blank');
  await page.goto(BASE + '/#check=me.example.com&vs=rival.example.com');
  await page.waitForSelector('.versus');
  check('a shared compare link runs both', (await page.locator('.versus .placard').count()) === 2);
  await page.unroute('**/api/scan');

  // one real scan through the real API, watching the progress arrive
  await page.goto('about:blank');
  await page.goto(BASE + '/');
  await page.evaluate(() => localStorage.clear());
  // always a real scan, even if an earlier run left this site in the server's short cache
  await page.route('**/api/scan', (route) => route.continue({ postData: JSON.stringify({ ...JSON.parse(route.request().postData()), fresh: true }) }));
  await page.evaluate(() => {
    window.__logRows = 0;
    new MutationObserver(() => { window.__logRows = Math.max(window.__logRows, document.querySelectorAll('.log li').length); }).observe(document.querySelector('#report'), { childList: true, subtree: true });
  });
  await page.fill('#url', 'github.com');
  await page.press('#url', 'Enter');
  await page.waitForFunction(() => { window.__sawProgress ||= document.querySelectorAll('.log li.is-done').length > 0; return document.querySelector('.head .placard'); }, null, { timeout: 30000, polling: 25 });
  const sawProgress = await page.evaluate(() => window.__sawProgress);
  check('the log showed all nine steps', (await page.evaluate(() => window.__logRows)) === 9);
  check('steps really streamed in before the report', sawProgress === true);
  await page.unroute('**/api/scan');
  check('a real scan of github.com renders', /^[A-F]$/.test(await page.locator('.head .placard .letter').innerText()), await page.locator('.head .placard .score').innerText());
  check('the real report has 22 rows', (await page.locator('.checks tbody tr').count()) === 22);
  if (SHOTS) await page.locator('#report').screenshot({ path: path.join(SHOTS, 'desktop-real-github.png') });

  // try-one buttons
  await page.goto('about:blank');
  await page.goto(BASE + '/');
  await page.click('[data-try="http.badssl.com"]');
  await page.waitForSelector('.head .placard', { timeout: 30000 });
  check('"try one" runs a real scan of a broken site', (await page.locator('.head .placard .letter').innerText()) === 'F');

  // print view hides the chrome
  await page.emulateMedia({ media: 'print' });
  check('print view hides the header and form', !(await page.locator('.bar').isVisible()) && !(await page.locator('#scan').isVisible()) && (await page.locator('.head .placard').isVisible()));
  check('print view hides the buttons and shows a title', !(await page.locator('.actions').isVisible()) && !(await page.locator('.fix-actions').isVisible()) && (await page.locator('.print-only').isVisible()));
  if (SHOTS) {
    await page.pdf({ path: path.join(SHOTS, 'report.pdf'), format: 'Letter', printBackground: true });
    await page.screenshot({ path: path.join(SHOTS, 'print.png'), fullPage: true });
  }
  await page.emulateMedia({ media: 'screen' });
  check('no console or CSP errors on desktop', errors.length === 0, errors.slice(0, 3).join(' | '));

  // storage blocked entirely: everything still works
  const locked = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  await locked.addInitScript(() => { Object.defineProperty(window, 'localStorage', { get() { throw new Error('blocked'); } }); });
  const lp = await locked.newPage();
  const lerr = [];
  lp.on('pageerror', (e) => lerr.push(String(e)));
  await lp.route('**/api/scan', json(live('private.example.com')));
  await lp.goto(BASE + '/');
  await lp.fill('#url', 'private.example.com');
  await lp.press('#url', 'Enter');
  await lp.waitForSelector('.head .placard');
  check('with browser storage blocked the report still renders', lerr.length === 0 && (await lp.locator('.short-head').isVisible()), lerr[0]);

  // phone
  const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 3 });
  const p = await phone.newPage();
  const perr = [];
  p.on('pageerror', (e) => perr.push(String(e)));
  p.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) perr.push(m.text()); });
  await p.goto(BASE + '/');
  const wide = () => p.evaluate(() => document.documentElement.scrollWidth - innerWidth);
  check('phone: no sideways scroll on the hero', (await wide()) <= 0, `${await wide()}px`);
  if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'phone-hero.png') });
  await p.tap('.bar-nav [data-sample]');
  await p.waitForSelector('.head .placard');
  check('phone: no sideways scroll on the report', (await wide()) <= 0, `${await wide()}px`);
  const box = await p.locator('#scan button[type="submit"]').boundingBox();
  check('phone: inspect button is a full-width 44px+ target', box.height >= 44 && box.width > 300, `${Math.round(box.width)}x${Math.round(box.height)}`);
  const reportHeight = await p.evaluate(() => document.querySelector('#report').getBoundingClientRect().height);
  check('phone: passing rows drop their explanation, failing ones keep it', await p.evaluate(() => {
    const vis = (s) => { const n = document.querySelector(s); return n && getComputedStyle(n).display !== 'none'; };
    return !vis('.checks tr[data-status="pass"] .what span') && vis('.checks tr[data-status="fail"] .what span');
  }), `report is ${Math.round(reportHeight)}px tall`);
  if (SHOTS) {
    await p.locator('#report').screenshot({ path: path.join(SHOTS, 'phone-report-full.png') });
    await p.evaluate(() => document.querySelector('.head').scrollIntoView());
    await p.screenshot({ path: path.join(SHOTS, 'phone-report-top.png') });
    await p.evaluate(() => document.querySelector('.spoof').scrollIntoView());
    await p.screenshot({ path: path.join(SHOTS, 'phone-spoof.png') });
  }
  await p.route('**/api/scan', async (route) => {
    const u = JSON.parse(route.request().postData()).url;
    return json(live(u.includes('rival') ? 'a-very-long-competitor-name-llc.example.com' : 'my-long-business-name.example.com', u.includes('rival') ? { grade: 'A', score: 91 } : {}))(route);
  });
  await p.fill('#url', 'me.example.com');
  await p.press('#url', 'Enter');
  await p.waitForSelector('[data-compare]');
  await p.tap('[data-compare]');
  await p.fill('#rival', 'rival.example.com');
  await p.press('#rival', 'Enter');
  await p.waitForSelector('.versus');
  check('phone: no sideways scroll with long names in compare', (await wide()) <= 0, `${await wide()}px`);
  if (SHOTS) await p.locator('.compare-slot').screenshot({ path: path.join(SHOTS, 'phone-compare.png') });
  await p.unroute('**/api/scan');
  await p.route('**/api/scan', () => { /* hold the request open */ });
  await p.goto('about:blank');
  await p.goto(BASE + '/');
  await p.fill('#url', 'slow.example.com');
  await p.press('#url', 'Enter');
  await p.waitForSelector('.log');
  check('phone: no sideways scroll on the progress log', (await wide()) <= 0, `${await wide()}px`);
  if (SHOTS) await p.screenshot({ path: path.join(SHOTS, 'phone-working.png') });
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
