/* GET /api/badge?host=example.com -> an SVG grade badge a site can show off. It always shows the grade
   the site earns right now, and the CDN keeps it for a day so a popular badge means one scan, not thousands. */
import { scanAddress } from '../lib/scan.js';
import { limited, visitor } from '../lib/limit.js';

const INK = '#090a0f', PAPER = '#f2f2ec', SIGNAL = '#00ff66';

export function badgeSvg(grade) {
  const known = /^[A-F]$/.test(grade);
  const shown = known ? grade : '?';
  const bg = grade === 'A' || grade === 'B' ? SIGNAL : PAPER;
  const label = known ? `DARE CHECK grade ${grade}` : 'DARE CHECK grade unavailable';
  return `<svg xmlns="http://www.w3.org/2000/svg" width="132" height="32" viewBox="0 0 132 32" role="img" aria-label="${label}"><title>${label}</title>` +
    `<rect width="132" height="32" fill="${INK}"/><rect x=".5" y=".5" width="131" height="31" fill="none" stroke="${PAPER}"/>` +
    `<rect x="100" width="32" height="32" fill="${bg}"/>` +
    `<text x="50" y="20.5" fill="${PAPER}" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="11" font-weight="700" letter-spacing=".8" text-anchor="middle">DARE CHECK</text>` +
    `<text x="116" y="22" fill="${INK}" font-family="ui-sans-serif,-apple-system,Helvetica,Arial,sans-serif" font-size="18" font-weight="700" text-anchor="middle">${shown}</text></svg>`;
}

export function createBadge({ run } = {}) {
  return async function handler(req, res) {
    const reply = (grade, cache) => {
      res.statusCode = 200;
      res.setHeader('content-type', 'image/svg+xml; charset=utf-8');
      res.setHeader('cache-control', cache);
      res.setHeader('cross-origin-resource-policy', 'cross-origin');
      res.setHeader('x-content-type-options', 'nosniff');
      res.end(badgeSvg(grade));
    };
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.statusCode = 405; res.setHeader('allow', 'GET, HEAD'); return res.end(); }
    if (limited(visitor(req))) return reply('?', 'no-store');
    const host = new URL(req.url, 'http://local').searchParams.get('host');
    const out = await scanAddress(host, { run });
    if (!out.ok) return reply('?', 'public, max-age=300, s-maxage=3600');
    return reply(out.grade, 'public, max-age=3600, s-maxage=86400, stale-while-revalidate=604800');
  };
}

export default createBadge();
