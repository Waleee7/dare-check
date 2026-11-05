/* Renders public/og.png, the card people see when the link is shared. Needs the dev server for the
   fonts and styles: PORT=5190 node server.js, then node scripts/og.cjs */
const { chromium } = require(process.env.HOME + '/.claude/scripts/node_modules/playwright');
const path = require('path');
const BASE = process.env.BASE || 'http://127.0.0.1:5190';

const CARD = (base) => `<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@500;700&display=swap">
<link rel="stylesheet" href="${base}/style.css">
<style>
  body { margin: 0; }
  .card { width: 1200px; height: 630px; display: grid; grid-template-columns: 760px 440px; background: var(--paper); color: var(--ink); overflow: hidden; }
  .left { padding: 52px 56px; border-right: 2px solid var(--ink); display: flex; flex-direction: column; justify-content: space-between; position: relative; }
  .left::before { content: ''; position: absolute; inset: 0; background: repeating-linear-gradient(to bottom, transparent 0 23px, rgba(242,242,236,.05) 23px 24px); }
  .left > * { position: relative; }
  .brand { font: 700 30px/1 var(--display); letter-spacing: .02em; }
  .brand b { color: var(--signal); }
  h1 { font-size: 118px; line-height: .88; letter-spacing: -.04em; margin: 0; }
  .sub { font: 400 22px/1.4 var(--mono); color: var(--dim); margin: 0; }
  .right { display: flex; flex-direction: column; }
  .grade { background: var(--ink); color: var(--paper); padding: 28px 32px; display: flex; flex-direction: column; flex: 1; justify-content: space-between; }
  .grade .l { font: 700 18px/1 var(--mono); letter-spacing: .14em; }
  .grade .g { font: 700 250px/.8 var(--display); letter-spacing: -.05em; }
  .row { display: flex; gap: 12px; align-items: center; padding: 17px 28px; border-top: 1px solid var(--ink); font: 400 19px/1.2 var(--mono); }
  .row .stamp { font-size: 15px; min-width: 96px; text-align: center; }
</style></head><body>
<div class="card">
  <div class="left">
    <div class="brand">DARE <b>CHECK</b></div>
    <h1>IS YOUR<br>WEBSITE<br>SAFE?</h1>
    <p class="sub">A free safety grade with plain-English fixes. No sign-up.</p>
  </div>
  <div class="right">
    <div class="grade"><span class="l">SAFETY GRADE</span><span class="g">C</span></div>
    <div class="row"><span class="stamp stamp--fail">[x] FAIL</span>Email spoofing</div>
    <div class="row"><span class="stamp stamp--warn">[!] WARN</span>Domain renewal</div>
    <div class="row"><span class="stamp stamp--pass">[+] PASS</span>HTTPS</div>
  </div>
</div></body></html>`;

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 630 } });
  // a blank page, because the live site's CSP rightly refuses the card's inline styles
  await page.setContent(CARD(BASE), { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(300);
  await page.screenshot({ path: path.join(__dirname, '..', 'public', 'og.png'), type: 'png' });
  await browser.close();
})();
