/* DARE CHECK page: runs a scan, renders the report. Everything from the scanned site (header
   values, cookie names, file URLs) is untrusted, so the DOM is built with textContent only. */
(() => {
  const EMAIL = ['jdare354', 'gmail.com'].join('@');
  const GROUPS = [['connection', 'Connection'], ['browser', 'Browser protections'], ['email', 'Email']];
  const MARK = { pass: '[+] Pass', warn: '[!] Warn', fail: '[x] Fail', skip: '[-] Skip' };
  const $ = (s, r = document) => r.querySelector(s);
  const form = $('#scan'), input = $('#url'), out = $('#report'), status = $('#status');
  const go = form.querySelector('button');
  let busy = false;

  function el(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === 'text') n.textContent = v;
      else if (k === 'class') n.className = v;
      else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) n.append(kid);
    return n;
  }
  const pad = (i) => String(i).padStart(2, '0');
  const stamp = (s) => el('span', { class: `stamp stamp--${s}`, text: MARK[s] });
  const when = (iso) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) + ' · ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
  };
  const say = (msg) => { status.textContent = ''; requestAnimationFrame(() => { status.textContent = msg; }); };

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); } catch {
      const t = el('textarea', { class: 'sr-only' }); t.value = text; document.body.append(t); t.select();
      try { document.execCommand('copy'); } catch { /* the code stays selectable on the page */ }
      t.remove();
    }
    const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = was; }, 1400);
  }

  function mailto(r) {
    const subject = `DARE CHECK report for ${r.host}`;
    const body = r.sample ? `Hi Josh,\n\nI saw DARE CHECK and want to know how my site does.\n` :
      `Hi Josh,\n\nMy site ${r.host} got a ${r.grade} (${r.score}/100) on DARE CHECK. Can you help me fix it?\n\n${location.href}\n`;
    return `mailto:${EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  function show(...nodes) {
    out.replaceChildren(...nodes);
    out.hidden = false;
  }

  function working(host) {
    out.setAttribute('aria-busy', 'true');
    show(el('div', { class: 'working' },
      el('p', { class: 'field-label', text: `Inspecting ${host}` }),
      el('div', { class: 'meter', 'aria-hidden': 'true' }),
      el('p', { class: 'hint', text: 'Visiting the homepage, reading the certificate and looking up email records…' })));
    out.scrollIntoView({ block: 'start' });
  }

  function oops(msg) {
    out.removeAttribute('aria-busy');
    show(el('div', { class: 'oops' },
      el('span', { class: 'stamp stamp--fail', text: "[x] Couldn't check" }),
      el('h2', { id: 'report-title', text: msg }),
      el('button', { type: 'button', text: 'Try another address', on: { click: () => { input.focus(); input.select(); } } })));
    say(msg);
    out.focus();
  }

  function render(r) {
    out.removeAttribute('aria-busy');
    const nodes = [];
    if (r.sample) nodes.push(el('p', { class: 'banner' }, el('b', { text: 'Sample report' }), ' · a made-up bakery, so you can see what you get'));

    const placard = el('div', { class: `placard${r.grade === 'A' ? ' is-a' : ''}` },
      el('span', { class: 'label', text: 'Safety grade' }),
      el('span', { class: 'letter', text: r.grade, 'aria-hidden': 'true' }),
      el('span', { class: 'score', text: `${r.score} / 100` }));
    const facts = el('div', { class: 'facts' },
      el('h2', { id: 'report-title', class: 'sr-only', text: `Grade ${r.grade}, ${r.score} out of 100, for ${r.host}` }),
      el('dl', {},
        el('dt', { text: 'Site' }), el('dd', { text: r.host }),
        el('dt', { text: 'Inspected' }), el('dd', { text: when(r.fetchedAt) }),
        el('dt', { text: 'Hosting' }), el('dd', { text: r.platform.name }),
        r.finalUrl && el('dt', { text: 'Landed on' }), r.finalUrl && el('dd', { text: r.finalUrl })),
      el('div', { class: 'counts' }, ['pass', 'warn', 'fail', 'skip'].filter((s) => r.counts[s]).map((s) =>
        el('span', { class: `stamp stamp--${s}`, text: `${r.counts[s]} ${s}` }))));
    const shareBtn = el('button', { type: 'button', text: 'Copy link', on: { click: (e) => copy(location.href, e.currentTarget) } });
    const actions = el('div', { class: 'actions' },
      !r.sample && shareBtn,
      el('button', { type: 'button', text: 'Print', on: { click: () => print() } }),
      el('button', { type: 'button', text: 'Check another', on: { click: () => { input.value = ''; input.focus(); scrollTo({ top: 0 }); } } }));
    nodes.push(el('div', { class: 'head' }, placard, facts, actions));
    if (r.notes.length) nodes.push(el('ul', { class: 'notes' }, r.notes.map((n) => el('li', { text: n }))));

    let i = 0;
    GROUPS.forEach(([id, label], g) => {
      const rows = r.checks.filter((c) => c.group === id);
      nodes.push(el('div', { class: 'group' },
        el('div', { class: 'rule' }, el('h2', { text: `${pad(g + 1)} / ${label}` }), el('span', { text: `${rows.length} checks` })),
        el('div', { class: 'table-wrap' }, el('table', { class: 'checks' },
          el('thead', {}, el('tr', {}, ['#', 'Check', 'Result', 'What we saw'].map((h) => el('th', { scope: 'col', text: h })))),
          el('tbody', {}, rows.map((c) => el('tr', { 'data-check': c.id, 'data-status': c.status },
            el('td', { class: 'n', text: pad(++i) }),
            el('td', { class: 'what' }, el('strong', { text: c.title }), el('span', { text: c.why })),
            el('td', { class: 'res' }, stamp(c.status)),
            el('td', { class: 'saw', text: c.saw }))))))));
    });

    if (r.fixes.length) {
      const gain = r.fixes.reduce((s, f) => s + f.points, 0);
      nodes.push(el('div', { class: 'group' },
        el('div', { class: 'rule' }, el('h2', { text: '04 / Fix these first' }), el('span', { text: `${r.fixes.length} fixes · up to +${gain} points` })),
        el('ol', { class: 'fixes' }, r.fixes.map((f, k) => el('li', { class: 'fix' },
          el('span', { class: 'n', text: pad(k + 1) }),
          el('h3', { text: f.title }),
          el('span', { class: 'pts', text: f.points ? `+${f.points} pts` : '' }),
          el('p', { text: f.text }),
          f.code && el('div', { class: 'code' },
            el('div', { class: 'code-bar' }, el('span', { text: f.file || '' }),
              el('button', { type: 'button', text: 'Copy', 'aria-label': `Copy the code for: ${f.title}`, on: { click: (e) => copy(f.code, e.currentTarget) } })),
            el('pre', {}, el('code', { text: f.code }))))))));
    } else {
      nodes.push(el('div', { class: 'group' }, el('div', { class: 'rule' }, el('h2', { text: '04 / Fixes' }), el('span', { text: 'none needed' }))));
    }

    nodes.push(el('div', { class: 'cta' },
      el('p', { text: r.fixes.length ? "Want it done for you? Send this report to Josh and he'll tell you what it takes." : 'Clean bill of health. Want a second pair of eyes on the rest of your site? Ask Josh.' }),
      el('a', { class: 'btn', href: mailto(r), text: 'Email Josh →' })));

    show(...nodes);
    say(`Inspection complete. ${r.host} gets a ${r.grade}, ${r.score} out of 100, with ${r.counts.fail} fails and ${r.counts.warn} warnings.`);
    out.focus({ preventScroll: true });
    out.scrollIntoView({ block: 'start' });
  }

  async function scan(raw, { push = true } = {}) {
    const value = String(raw).trim();
    if (!value) { oops('Type a website address, like yourbusiness.com.'); return; }
    if (busy) return;
    busy = true; go.disabled = true;
    const host = value.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].toLowerCase();
    working(host);
    say(`Inspecting ${host}`);
    try {
      const res = await fetch('/api/scan', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: value }) });
      const r = await res.json().catch(() => ({ ok: false, error: 'The checker sent back something unexpected. Try again.' }));
      if (!r.ok) return oops(r.error || "That site couldn't be checked.");
      if (push) history.replaceState(null, '', '#check=' + encodeURIComponent(r.host));
      render(r);
    } catch {
      oops("Couldn't reach the checker. Check your connection and try again.");
    } finally {
      busy = false; go.disabled = false;
    }
  }

  async function sample() {
    try {
      const r = await (await fetch('sample.json')).json();
      history.replaceState(null, '', location.pathname);
      render(r);
    } catch { oops("The sample report didn't load. Try again."); }
  }

  // the hero's preview card: the sample's grade and one row of each result
  async function readout() {
    const box = $('[data-readout]');
    if (!box) return;
    try {
      const r = await (await fetch('sample.json')).json();
      const pickOne = (s) => r.checks.find((c) => c.status === s);
      box.replaceChildren(
        el('div', { class: 'readout-top' }, el('span', { text: `Sample readout · ${r.host.replace(/^www\./, '')}` }),
          el('span', { class: 'readout-grade' }, el('b', { text: r.grade }), el('span', { text: `${r.score}/100` }))),
        el('ul', { 'aria-label': 'Three sample results' }, ['fail', 'warn', 'pass'].map(pickOne).filter(Boolean).map((c) =>
          el('li', {}, stamp(c.status), el('span', { text: c.title })))),
        el('button', { type: 'button', on: { click: sample } }, 'Open the full sample report', el('span', { 'aria-hidden': 'true', text: '→' })));
      box.hidden = false;
    } catch { /* the preview is optional */ }
  }
  readout();

  form.addEventListener('submit', (e) => { e.preventDefault(); scan(input.value); });
  for (const b of document.querySelectorAll('[data-sample]')) b.addEventListener('click', sample);
  for (const a of document.querySelectorAll('[data-email]')) a.href = `mailto:${EMAIL}?subject=${encodeURIComponent('DARE CHECK: help with my website')}`;

  // a shared link (#check=example.com) runs the scan on load, or when the hash changes later
  const fromHash = () => {
    const m = location.hash.match(/^#check=([^&]+)$/);
    if (m) { input.value = decodeURIComponent(m[1]); scan(input.value, { push: false }); }
  };
  addEventListener('hashchange', fromHash);
  fromHash();

  window.DARECHECK = { render, scan };   // test hook
})();
