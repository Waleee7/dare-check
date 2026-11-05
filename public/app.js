/* DARE CHECK page: runs a scan, shows real progress, renders the report. Everything from the scanned
   site (header values, cookie names, file URLs) is untrusted, so the DOM is built with textContent only. */
(() => {
  const EMAIL = ['jdare354', 'gmail.com'].join('@');
  const GROUPS = [['connection', 'Connection'], ['browser', 'Browser protections'], ['email', 'Email'], ['trust', 'Reputation and upkeep']];
  const STEPS = [['https', 'Secure connection'], ['cert', 'Certificate'], ['http', 'Plain http'], ['www', 'Other spelling'], ['email', 'Email records'], ['dkim', 'Signing keys'], ['blocklist', 'Malware filters'], ['domain', 'Domain registration'], ['software', 'Page contents']];
  const MARK = { pass: '[+] Pass', warn: '[!] Warn', fail: '[x] Fail', skip: '[-] Skip', info: '[i] Info' };
  const RANK = { pass: 3, warn: 2, fail: 1 };
  const AUTO_RENEW = /let's encrypt|google trust|amazon|cloudflare|zerossl/i;   // these renew themselves when set up
  const HISTORY_KEY = 'dc-history';
  const $ = (s, r = document) => r.querySelector(s);
  const form = $('#scan'), input = $('#url'), out = $('#report'), status = $('#status');
  const go = form.querySelector('button[type="submit"]');
  let busy = false;
  let current = null;       // the report on screen
  let joshFor = null;       // the site named in a link Josh sent

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
  const day = (iso) => new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
  const say = (msg) => { status.textContent = ''; requestAnimationFrame(() => { status.textContent = msg; }); };
  const reportUrl = (host) => `${location.origin}${location.pathname}#check=${encodeURIComponent(host)}`;

  async function copy(text, btn) {
    try { await navigator.clipboard.writeText(text); } catch {
      const t = el('textarea', { class: 'sr-only' }); t.value = text; document.body.append(t); t.select();
      try { document.execCommand('copy'); } catch { /* the code stays selectable on the page */ }
      t.remove();
    }
    const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = was; }, 1400);
  }

  /* ---------------- this browser's memory (optional: everything works without it) ---------------- */

  function recentChecks() {
    try { const v = JSON.parse(localStorage.getItem(HISTORY_KEY)); return Array.isArray(v) ? v.filter((h) => h && typeof h.host === 'string') : []; } catch { return []; }
  }
  function remember(r) {
    try { localStorage.setItem(HISTORY_KEY, JSON.stringify([{ host: r.host, grade: r.grade, score: r.score, at: r.fetchedAt }, ...recentChecks().filter((h) => h.host !== r.host)].slice(0, 6))); } catch { /* private window */ }
  }
  function forget() {
    try { localStorage.removeItem(HISTORY_KEY); } catch { /* nothing to clear */ }
    showRecent();
  }
  function showRecent() {
    const box = $('[data-recent]');
    const list = recentChecks();
    box.hidden = !list.length;
    box.replaceChildren(...(list.length ? [
      el('span', { class: 'recent-label', text: 'Your recent checks (only on this device):' }),
      ...list.map((h) => el('button', { type: 'button', class: 'link', on: { click: () => { input.value = h.host; scan(h.host); } } }, `${h.host} `, el('b', { text: h.grade }))),
      el('button', { type: 'button', class: 'link link--dim', text: 'Clear', on: { click: forget } }),
    ] : []));
  }

  /* ---------------- mail and calendar links ---------------- */

  function mailto(r) {
    const subject = `DARE CHECK report for ${r.host}`;
    if (r.sample) return `mailto:${EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent('Hi Josh,\n\nI saw DARE CHECK and want to know how my site does.\n')}`;
    const top = r.fixes.slice(0, 3).map((f) => `- ${f.title}`).join('\n');
    const body = `Hi Josh,\n\nMy site ${r.host} got a ${r.grade} (${r.score}/100) on DARE CHECK.${top ? ` The top items:\n\n${top}\n\n` : '\n\n'}Can you help me fix it?\n\n${reportUrl(r.host)}\n`;
    return `mailto:${EMAIL}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  // for whoever actually maintains the site: short enough for every mail app to accept
  function webPersonMail(r) {
    const lines = r.fixes.slice(0, 8).map((f, i) => `${i + 1}. ${f.title} (${f.time})`).join('\n');
    const body = `Hi,\n\nI ran a free safety check on ${r.host} and it got a ${r.grade} (${r.score}/100). Can you take care of these?\n\n${lines}\n\nThe full report, with the exact code for each one:\n${reportUrl(r.host)}\n`;
    return `mailto:?subject=${encodeURIComponent(`Website safety fixes for ${r.host}`)}&body=${encodeURIComponent(body)}`;
  }

  const fixesAsText = (r) => [`DARE CHECK: ${r.host} got ${r.grade} (${r.score}/100)`, reportUrl(r.host), '',
    ...r.fixes.flatMap((f, i) => [`${i + 1}. ${f.title}${f.points ? ` (+${f.points} points)` : ''}`, `   ${f.time} · ${f.who}`, `   ${f.text}`, ...(f.code ? [`   ${f.file}:`, ...f.code.split('\n').map((l) => `     ${l}`)] : []), ''])].join('\n');

  function calendarFile(title, dueIso, note) {
    const yyyymmdd = (d) => d.toISOString().slice(0, 10).replace(/-/g, '');
    const esc = (s) => String(s).replace(/([\\,;])/g, '\\$1').replace(/\n/g, '\\n');
    const remind = new Date(Math.max(Date.parse(dueIso) - 30 * 86400000, Date.now() + 86400000));
    const after = new Date(remind.getTime() + 86400000);
    return ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//DARE CHECK//Reminder//EN', 'CALSCALE:GREGORIAN', 'BEGIN:VEVENT',
      `UID:${yyyymmdd(remind)}-${Math.random().toString(36).slice(2)}@dare-check`,
      `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '')}`,
      `DTSTART;VALUE=DATE:${yyyymmdd(remind)}`, `DTEND;VALUE=DATE:${yyyymmdd(after)}`,
      `SUMMARY:${esc(title)}`, `DESCRIPTION:${esc(note)}`, 'BEGIN:VALARM', 'ACTION:DISPLAY', `DESCRIPTION:${esc(title)}`, 'TRIGGER:PT9H', 'END:VALARM', 'END:VEVENT', 'END:VCALENDAR', ''].join('\r\n');
  }
  function saveReminder(name, title, dueIso, note, btn) {
    const url = URL.createObjectURL(new Blob([calendarFile(title, dueIso, note)], { type: 'text/calendar;charset=utf-8' }));
    const a = el('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    const was = btn.textContent; btn.textContent = 'Saved'; setTimeout(() => { btn.textContent = was; }, 1400);
  }

  /* ---------------- states ---------------- */

  function show(...nodes) {
    out.replaceChildren(...nodes);
    out.hidden = false;
  }

  let clock = null;
  function working(host) {
    clearInterval(clock);
    out.setAttribute('aria-busy', 'true');
    const timer = el('span', { class: 'clock', text: '00:00' });
    const t0 = Date.now();
    clock = setInterval(() => { const s = Math.floor((Date.now() - t0) / 1000); timer.textContent = `${pad(Math.floor(s / 60))}:${pad(s % 60)}`; }, 500);
    const count = el('span', { class: 'log-count', text: `0 / ${STEPS.length}` });
    const rows = new Map();
    const list = el('ol', { class: 'log' }, STEPS.map(([id, label], i) => {
      const note = el('span', { class: 'log-note', text: 'waiting' });
      const li = el('li', { 'data-step': id }, el('span', { class: 'log-n', text: pad(i + 1) }), el('span', { class: 'log-label', text: label }), note);
      rows.set(id, { li, note });
      return li;
    }));
    show(el('div', { class: 'working' },
      el('div', { class: 'working-top' }, el('p', { class: 'field-label', text: `Inspecting ${host}` }), el('span', {}, count, ' · ', timer)),
      el('div', { class: 'meter', 'aria-hidden': 'true' }),
      list,
      el('p', { class: 'hint', text: 'Every line is a real result as it comes back. Nothing is changed on the site.' })));
    out.scrollIntoView({ block: 'start' });
    let done = 0;
    return ({ id, note }) => {
      const row = rows.get(id);
      if (!row || row.li.classList.contains('is-done')) return;
      row.li.classList.add('is-done');
      row.note.textContent = note || 'done';
      count.textContent = `${++done} / ${STEPS.length}`;
    };
  }

  function oops(msg) {
    clearInterval(clock);
    out.removeAttribute('aria-busy');
    show(el('div', { class: 'oops' },
      el('span', { class: 'stamp stamp--fail', text: "[x] Couldn't check" }),
      el('h2', { id: 'report-title', text: msg }),
      el('button', { type: 'button', text: 'Try another address', on: { click: () => { input.focus(); input.select(); } } })));
    say(msg);
    out.focus();
  }

  /* ---------------- report parts ---------------- */

  function shortVersion(r, previous) {
    const s = r.summary;
    const delta = previous && previous.score !== r.score ? r.score - previous.score : 0;
    return el('div', { class: 'short' },
      el('p', { class: 'field-label', text: 'The short version' }),
      el('p', { class: 'short-head', text: s.headline }),
      s.risks.length > 0 && el('ul', { class: 'short-risks' }, s.risks.map((x) => el('li', {}, stamp(x.status), el('span', { text: x.text })))),
      s.good.length > 0 && el('p', { class: 'short-good' }, stamp('pass'), el('span', { text: `Working: ${s.good.join(', ')}.` })),
      (s.next || s.potential) && el('div', { class: 'short-next' },
        s.next && el('p', {}, el('b', { text: 'Fastest win: ' }), `${s.next.title} · ${s.next.time} · +${s.next.points} points.`),
        s.potential && el('p', {}, el('b', { text: 'Fix everything below: ' }), `${r.grade} ${r.score} becomes ${s.potential.grade} ${s.potential.score}.`),
        el('p', { class: 'short-jump' }, el('button', { type: 'button', class: 'link', text: 'Jump to the fixes', on: { click: () => { $('[data-fixes]')?.scrollIntoView({ block: 'start' }); } } }))),
      previous && el('p', { class: 'short-delta' }, el('b', { text: 'Since your last check: ' }),
        delta > 0 ? `up ${delta} points, from ${previous.grade} ${previous.score}. Nice work.` : delta < 0 ? `down ${-delta} points, from ${previous.grade} ${previous.score}.` : 'no change in the score.'));
  }

  function spoofCard(r) {
    const domain = r.spoof.domain;
    return el('div', { class: 'spoof' },
      el('div', { class: 'spoof-text' },
        el('h3', { text: 'What a scammer could send today' }),
        el('p', { text: `Nothing tells inboxes to throw this out, so a fake message "from" ${domain} can reach your customers. Fake invoices are the classic version.` }),
        el('p', { class: 'hint', text: 'Illustration only. No email was sent.' })),
      el('div', { class: 'mail', role: 'img', 'aria-label': `Illustration of a fake email claiming to be from billing at ${domain}` },
        el('dl', {},
          el('dt', { text: 'From' }), el('dd', {}, 'Accounts <', el('b', { text: `billing@${domain}` }), '>'),
          el('dt', { text: 'Subject' }), el('dd', { text: 'Invoice 4471 is past due' })),
        el('p', { text: 'Hi, our bank details have changed. Please send this month\'s payment to the new account below by Friday.' })));
  }

  function reminders(r) {
    const items = [];
    if (r.dates?.domain) {
      items.push(['Domain renewal', r.dates.domain, 'domain', `Renew ${r.domain}`, `Your domain ${r.domain} comes due on ${day(r.dates.domain)}. Check that auto-renew is on and the card on file is good.`]);
    }
    if (r.dates?.cert && !AUTO_RENEW.test(r.dates.certIssuer || '')) {
      items.push(['Security certificate', r.dates.cert, 'certificate', `Renew the certificate for ${r.host}`, `The certificate for ${r.host} expires on ${day(r.dates.cert)}.`]);
    }
    if (!items.length || r.sample) return null;
    return el('div', { class: 'group' },
      el('div', { class: 'rule' }, el('h2', { text: 'Dates to remember' }), el('span', { text: 'Reminder 30 days before' })),
      el('ul', { class: 'dates' }, items.map(([label, iso, kind, title, note]) => el('li', {},
        el('span', {}, el('b', { text: label }), ` · ${day(iso)}`),
        el('button', { type: 'button', text: 'Add to calendar', 'aria-label': `Add a ${label.toLowerCase()} reminder to your calendar`, on: { click: (e) => saveReminder(`${kind}-reminder-${r.domain}.ics`, title, iso, note, e.currentTarget) } })))));
  }

  function badgeOffer(r) {
    if (r.sample || !['A', 'B'].includes(r.grade)) return null;
    const src = `${location.origin}/api/badge?host=${encodeURIComponent(r.host)}`;
    const code = `<a href="${reportUrl(r.host)}"><img src="${src}" alt="DARE CHECK safety grade" width="132" height="32"></a>`;
    return el('div', { class: 'group' },
      el('div', { class: 'rule' }, el('h2', { text: 'You earned this' }), el('span', { text: 'Shows your live grade' })),
      el('div', { class: 'badge-box' },
        el('img', { src: `/api/badge?host=${encodeURIComponent(r.host)}`, alt: `DARE CHECK grade ${r.grade}`, width: 132, height: 32 }),
        el('div', { class: 'code' },
          el('div', { class: 'code-bar' }, el('span', { text: 'Paste this into your site' }), el('button', { type: 'button', text: 'Copy', on: { click: (e) => copy(code, e.currentTarget) } })),
          el('pre', {}, el('code', { text: code })))));
  }

  function render(r, { previous = null } = {}) {
    clearInterval(clock);
    out.removeAttribute('aria-busy');
    current = r;
    const nodes = [];
    nodes.push(el('p', { class: 'print-only', text: `DARE CHECK safety inspection · ${r.host} · ${when(r.fetchedAt)}` }));
    if (r.sample) nodes.push(el('p', { class: 'banner' }, el('b', { text: 'Sample report' }), ' · a made-up bakery, so you can see what you get'));
    else if (r.host === joshFor) nodes.push(el('p', { class: 'banner' }, el('b', { text: 'Josh Dare ran this for you' }), ' · it only read public information, and nothing on your site was changed'));

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
        r.builder && el('dt', { text: 'Built with' }), r.builder && el('dd', { text: r.builder.name }),
        r.registrar && el('dt', { text: 'Registrar' }), r.registrar && el('dd', { text: r.registrar }),
        r.finalUrl && el('dt', { text: 'Landed on' }), r.finalUrl && el('dd', { text: r.finalUrl })),
      el('div', { class: 'counts' }, ['pass', 'warn', 'fail', 'skip'].filter((s) => r.counts[s]).map((s) =>
        el('span', { class: `stamp stamp--${s}`, text: `${r.counts[s]} ${s}` }))));
    const actions = el('div', { class: 'actions' },
      !r.sample && el('button', { type: 'button', text: 'Copy link', on: { click: (e) => copy(location.href, e.currentTarget) } }),
      !r.sample && el('button', { type: 'button', text: 'Check again', 'data-recheck': true, on: { click: () => scan(r.host, { fresh: true }) } }),
      !r.sample && el('button', { type: 'button', text: 'Compare with a competitor', 'data-compare': true, 'aria-expanded': 'false', on: { click: toggleCompare } }),
      el('button', { type: 'button', text: 'Print', on: { click: () => print() } }),
      el('button', { type: 'button', text: 'Check another', on: { click: () => { input.value = ''; input.focus(); scrollTo({ top: 0 }); } } }));
    nodes.push(el('div', { class: 'head' }, placard, facts, actions));
    nodes.push(el('div', { class: 'compare-slot', 'data-compare-slot': true }));
    if (r.caveat) nodes.push(el('p', { class: 'caveat', 'data-caveat': true }, stamp('warn'), el('span', { text: r.caveat })));
    nodes.push(shortVersion(r, previous));
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
            el('td', { class: 'saw', text: c.saw })))))),
        id === 'email' && r.spoof && spoofCard(r)));
    });

    const fixN = pad(GROUPS.length + 1);
    if (r.fixes.length) {
      const gain = r.fixes.reduce((s, f) => s + f.points, 0);
      nodes.push(el('div', { class: 'group', 'data-fixes': true },
        el('div', { class: 'rule' }, el('h2', { text: `${fixN} / Fix these first` }), el('span', { text: `${r.fixes.length} ${r.fixes.length === 1 ? 'fix' : 'fixes'}${gain ? ` · up to +${gain} points` : ''}` })),
        !r.sample && el('div', { class: 'fix-actions' },
          el('a', { class: 'btn', href: webPersonMail(r), text: 'Send to my web person' }),
          el('button', { type: 'button', text: 'Copy all fixes', on: { click: (e) => copy(fixesAsText(r), e.currentTarget) } })),
        el('ol', { class: 'fixes' }, r.fixes.map((f, k) => el('li', { class: 'fix' },
          el('span', { class: 'n', text: pad(k + 1) }),
          el('h3', { text: f.title }),
          el('span', { class: 'pts', text: f.points ? `+${f.points} pts` : '' }),
          el('p', { class: 'fix-meta', text: `${f.time} · ${f.who}` }),
          el('p', { text: f.text }),
          f.links && el('p', { class: 'fix-links' }, f.links.map((l) => el('a', { href: l.href, rel: 'noopener', target: '_blank', text: l.label }))),
          f.code && el('div', { class: 'code' },
            el('div', { class: 'code-bar' }, el('span', { text: f.file || '' }),
              el('button', { type: 'button', text: 'Copy', 'aria-label': `Copy the code for: ${f.title}`, on: { click: (e) => copy(f.code, e.currentTarget) } })),
            el('pre', {}, el('code', { text: f.code }))))))));
    } else {
      nodes.push(el('div', { class: 'group' }, el('div', { class: 'rule' }, el('h2', { text: `${fixN} / Fixes` }), el('span', { text: 'none needed' }))));
    }

    nodes.push(reminders(r), badgeOffer(r));
    nodes.push(el('div', { class: 'cta' },
      el('p', { text: r.fixes.length ? "Want it done for you? Send this report to Josh and he'll tell you what it takes." : 'Clean bill of health. Want a second pair of eyes on the rest of your site? Ask Josh.' }),
      el('a', { class: 'btn', href: mailto(r), text: 'Email Josh →' })));

    show(...nodes.filter(Boolean));
    say(`Inspection complete. ${r.host} gets a ${r.grade}, ${r.score} out of 100, with ${r.counts.fail} fails and ${r.counts.warn} warnings. ${r.summary.headline}`);
    out.focus({ preventScroll: true });
    out.scrollIntoView({ block: 'start' });
  }

  /* ---------------- compare with a competitor ---------------- */

  function toggleCompare(e) {
    const slot = $('[data-compare-slot]');
    const open = slot.childElementCount > 0;
    e.currentTarget.setAttribute('aria-expanded', String(!open));
    if (open) return slot.replaceChildren();
    const rival = el('input', { id: 'rival', type: 'text', inputmode: 'url', autocapitalize: 'off', spellcheck: 'false', placeholder: 'theircompany.com', 'aria-label': "Competitor's website address" });
    slot.replaceChildren(el('form', { class: 'rival', novalidate: true, on: { submit: (ev) => { ev.preventDefault(); compare(rival.value); } } },
      el('label', { class: 'field-label', for: 'rival', text: "Competitor's website" }),
      el('div', { class: 'field' }, rival, el('button', { type: 'submit', text: 'Compare →' }))));
    rival.focus();
  }

  function versus(a, b) {
    const rows = a.checks.map((c) => {
      const o = b.checks.find((x) => x.id === c.id);
      return { c, o, gap: (RANK[c.status] ?? 0) && (RANK[o?.status] ?? 0) ? RANK[c.status] - RANK[o.status] : 0 };
    }).filter((x) => x.o && x.c.status !== 'info');
    const ahead = rows.filter((x) => x.gap > 0).length, behind = rows.filter((x) => x.gap < 0).length;
    const scoreLine = a.score === b.score ? 'Tied on score.' : a.score > b.score ? `${a.host} is ahead by ${a.score - b.score} points.` : `${b.host} is ahead by ${b.score - a.score} points.`;
    const diffs = rows.filter((x) => x.gap !== 0).sort((x, y) => Math.abs(y.gap) - Math.abs(x.gap) || x.gap - y.gap);
    const even = rows.filter((x) => x.gap === 0);
    const placard = (r) => el('div', { class: `placard placard--small${r.grade === 'A' ? ' is-a' : ''}` },
      el('span', { class: 'label', text: r.host }), el('span', { class: 'letter', text: r.grade }), el('span', { class: 'score', text: `${r.score} / 100` }));
    const table = (list) => el('div', { class: 'table-wrap' }, el('table', { class: 'checks vs-table' },
      el('thead', {}, el('tr', {}, el('th', { scope: 'col', text: 'Check' }), el('th', { scope: 'col', text: a.host }), el('th', { scope: 'col', text: b.host }))),
      el('tbody', {}, list.map(({ c, o, gap }) => el('tr', { 'data-gap': gap > 0 ? 'ahead' : gap < 0 ? 'behind' : 'even' },
        el('td', { class: 'what' }, el('strong', { text: c.title })), el('td', { class: 'res' }, stamp(c.status)), el('td', { class: 'res' }, stamp(o.status)))))));
    return el('div', { class: 'versus' },
      el('div', { class: 'versus-head' }, placard(a), placard(b),
        el('div', { class: 'versus-say' },
          el('p', { class: 'short-head', text: scoreLine }),
          el('p', { text: diffs.length ? `${a.host} wins ${ahead} and loses ${behind} of the ${diffs.length} ${diffs.length === 1 ? 'check' : 'checks'} where you differ.` : 'Same result on every check.' }))),
      diffs.length > 0 && table(diffs),
      even.length > 0 && el('details', { class: 'vs-even' }, el('summary', { text: `${even.length} more ${even.length === 1 ? 'check' : 'checks'} with no winner` }), table(even)));
  }

  async function compare(raw) {
    const value = String(raw).trim();
    const slot = $('[data-compare-slot]');
    if (!value || !current || busy) return;
    busy = true;
    const panel = el('div', { class: 'working' }, el('p', { class: 'field-label', text: `Inspecting ${value}` }), el('div', { class: 'meter', 'aria-hidden': 'true' }));
    slot.replaceChildren(panel);
    say(`Inspecting ${value}`);
    try {
      const b = await request(value);
      if (!b.ok) {
        slot.replaceChildren(el('div', { class: 'oops oops--small' }, el('span', { class: 'stamp stamp--fail', text: "[x] Couldn't compare" }), el('p', { text: b.error || "That site couldn't be checked." })));
        return say(b.error || "That site couldn't be checked.");
      }
      slot.replaceChildren(versus(current, b));
      history.replaceState(null, '', `#check=${encodeURIComponent(current.host)}&vs=${encodeURIComponent(b.host)}${current.host === joshFor ? '&from=josh' : ''}`);
      say(`${current.host} scores ${current.score}, ${b.host} scores ${b.score}.`);
      slot.scrollIntoView({ block: 'start' });
    } catch {
      slot.replaceChildren(el('div', { class: 'oops oops--small' }, el('p', { text: "Couldn't reach the checker. Try again." })));
    } finally {
      busy = false;
    }
  }

  /* ---------------- talking to the API ---------------- */

  async function request(value, { fresh = false, onStep } = {}) {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: onStep ? 'application/x-ndjson, application/json' : 'application/json' },
      body: JSON.stringify({ url: value, ...(fresh ? { fresh: true } : {}) }),
    });
    const type = res.headers.get('content-type') || '';
    if (!type.includes('ndjson') || !res.body) return res.json().catch(() => ({ ok: false, error: 'The checker sent back something unexpected. Try again.' }));
    const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
    let buf = '', final = null;
    for (;;) {
      const { value: chunk, done } = await reader.read();
      if (chunk) buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const m = JSON.parse(line);
        if (m.type === 'step') onStep?.(m);
        else if (m.type === 'report') final = m.report;
        else if (m.type === 'error') final = { ok: false, error: m.error };
      }
      if (done) break;
    }
    return final ?? { ok: false, error: 'The check got cut off. Try again.' };
  }

  async function scan(raw, { push = true, fresh = false, vs = null } = {}) {
    const value = String(raw).trim();
    if (!value) { oops('Type a website address, like yourbusiness.com.'); return; }
    if (busy) return;
    busy = true; go.disabled = true;
    const host = value.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].toLowerCase();
    const tick = working(host);
    say(`Inspecting ${host}`);
    let ran = false;
    try {
      const r = await request(value, { fresh, onStep: tick });
      if (!r.ok) return oops(r.error || "That site couldn't be checked.");
      if (push) history.replaceState(null, '', `#check=${encodeURIComponent(r.host)}${r.host === joshFor ? '&from=josh' : ''}`);
      const previous = recentChecks().find((h) => h.host === r.host && h.at !== r.fetchedAt) ?? null;
      render(r, { previous });
      remember(r);
      showRecent();
      ran = true;
    } catch {
      oops("Couldn't reach the checker. Check your connection and try again.");
    } finally {
      busy = false; go.disabled = false;
    }
    if (ran && vs) {
      const btn = $('[data-compare]');
      if (btn) { toggleCompare({ currentTarget: btn }); await compare(vs); }
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
  showRecent();

  form.addEventListener('submit', (e) => { e.preventDefault(); scan(input.value); });
  for (const b of document.querySelectorAll('[data-sample]')) b.addEventListener('click', sample);
  for (const b of document.querySelectorAll('[data-try]')) b.addEventListener('click', () => { input.value = b.dataset.try; scan(b.dataset.try); });
  for (const a of document.querySelectorAll('[data-email]')) a.href = `mailto:${EMAIL}?subject=${encodeURIComponent('DARE CHECK: help with my website')}`;
  for (const b of document.querySelectorAll('[data-copy]')) b.addEventListener('click', () => copy(b.closest('.code').querySelector('code').textContent, b));

  // a shared link (#check=example.com&vs=rival.com) runs the scan on load, or when the hash changes later
  const fromHash = () => {
    if (!location.hash.startsWith('#check=')) return;
    const p = new URLSearchParams(location.hash.slice(1));
    const target = p.get('check');
    if (!target) return;
    joshFor = p.get('from') === 'josh' ? target.toLowerCase() : null;
    input.value = target;
    scan(target, { push: false, vs: p.get('vs') });
  };
  addEventListener('hashchange', fromHash);
  fromHash();

  window.DARECHECK = { render, scan };   // test hook
})();
