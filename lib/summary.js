/* "The short version": what a business owner should take from the report, in sentences they can
   repeat to someone else. Pure rules, no AI, so the same site always reads the same way. */

const HEADLINES = {
  A: 'The basics are covered.',
  B: 'Mostly solid, with a few gaps.',
  C: 'Some real gaps worth fixing.',
  D: 'Several real problems here.',
  F: 'This needs attention soon.',
};

// worst first: the top three that apply become the summary
const RISKS = [
  ['blocklist', 'fail', "Security filters list your site as dangerous, so some customers can't reach it. That can mean the site has been hacked."],
  ['https', 'fail', "There's no working secure connection, so anyone on the same Wi-Fi can read or change what customers see and type."],
  ['cert', 'fail', 'Your security certificate is broken or about to run out, which puts a full-page warning in front of your site.'],
  ['renewal', 'fail', 'Your domain is about to expire. If it lapses, your site and email stop working and someone else can buy the name.'],
  ['forms', 'fail', 'A form on your homepage sends what people type without encryption.'],
  ['software', 'fail', 'Your site runs a WordPress version that WordPress itself lists as insecure.'],
  ['dmarc', 'fail', 'Nothing stops scammers from sending email that looks like it came from you.'],
  ['spf', 'fail', "Inboxes can't tell which servers are allowed to send your email."],
  ['mixed', 'fail', 'Your secure page loads code over plain http, which an attacker can swap.'],
  ['www', 'fail', 'People who type www in front of your address get a security warning.'],
  ['redirect', 'fail', 'People who type your address without https:// stay on the insecure version.'],
  ['dmarc', 'warn', 'Fake email using your domain still gets delivered, because your DMARC record only watches.'],
  ['cert', 'warn', 'Your security certificate runs out soon. If it lapses, visitors get a full-page warning.'],
  ['renewal', 'warn', 'Your domain renews within a month. Make sure auto-renew is on and the card on file is good.'],
  ['software', 'warn', 'Your site loads old software with published security holes.'],
  ['hsts', 'warn', "Browsers aren't told to insist on your secure site, which leaves a gap on public Wi-Fi."],
  ['framing', 'warn', 'Scam pages can load your site invisibly and trick people into clicking your buttons.'],
  ['www', 'warn', "People who type your address with or without www don't all land on your site."],
  ['csp', 'warn', "Scripts aren't fully locked down, so injected code could still run."],
  ['cookies', 'warn', 'Some of your cookies are missing the flags that keep them from being stolen.'],
];

const GOOD = { connection: 'secure connection', browser: 'browser protections', email: 'email protection', trust: 'reputation and upkeep' };

export function summarize({ grade, checks, fixes, potential }) {
  const statusOf = Object.fromEntries(checks.map((c) => [c.id, c.status]));
  const risks = RISKS.filter(([id, status]) => statusOf[id] === status).slice(0, 3).map(([id, status, text]) => ({ id, status, text }));

  // a group only counts as working if nothing in it warned or failed, and at least one check actually passed
  const good = Object.keys(GOOD).filter((g) => {
    const rows = checks.filter((c) => c.group === g);
    return rows.some((c) => c.status === 'pass') && !rows.some((c) => c.status === 'warn' || c.status === 'fail');
  }).map((g) => GOOD[g]);

  // the most points for the least time
  const earning = fixes.filter((f) => f.points > 0);
  const next = earning.length ? [...earning].sort((a, b) => b.points / b.mins - a.points / a.mins)[0] : null;

  return {
    headline: HEADLINES[grade],
    risks, good,
    next: next ? { title: next.title, points: next.points, time: next.time, who: next.who } : null,
    potential: potential ?? null,
  };
}
