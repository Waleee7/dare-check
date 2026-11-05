/* Reads a scanned page's HTML. The page is written by a stranger, so nothing here backtracks: a walk
   over the tags with a hard work budget, and small regexes that only ever see a single short tag.
   Comments and the insides of scripts, styles and <noscript> aren't parsed, because browsers
   don't load anything from them. */
import { registrable } from './domains.js';

const MAX_TAG = 2048;
const WORK_BUDGET = 4_000_000;   // characters of tag-scanning; a normal 256 KB page uses well under a tenth of this
const RAW_TEXT = ['script', 'style', 'textarea', 'title', 'noscript', 'template'];
const CLOSERS = Object.fromEntries(RAW_TEXT.map((n) => [n, new RegExp(`</${n}`, 'gi')]));
const isLetter = (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
const isNameChar = (c) => (c >= 48 && c <= 57) || isLetter(c);

export function* eachTag(html = '') {
  const n = html.length;
  let i = 0, budget = WORK_BUDGET;
  while (i < n && budget > 0) {
    i = html.indexOf('<', i);
    if (i === -1) return;
    if (html.startsWith('<!--', i)) {
      const end = html.indexOf('-->', i + 4);
      if (end === -1) return;
      i = end + 3;
      continue;
    }
    if (!isLetter(html.charCodeAt(i + 1))) { i++; continue; }   // "<3" in some text, or a closing tag
    let j = i + 1;
    while (j < n && j - i <= 16 && isNameChar(html.charCodeAt(j))) j++;
    // find the closing ">", ignoring any inside quoted attribute values
    let quote = 0, end = -1;
    const stop = Math.min(n, j + MAX_TAG);
    for (let k = j; k < stop; k++) {
      const c = html.charCodeAt(k);
      if (quote) { if (c === quote) quote = 0; } else if (c === 34 || c === 39) quote = c; else if (c === 62) { end = k; break; }
    }
    budget -= (end === -1 ? stop : end) - j + 1;
    if (end === -1) { i = j; continue; }
    const name = html.slice(i + 1, j).toLowerCase();
    yield { name, inner: html.slice(j, end) };
    i = end + 1;
    if (CLOSERS[name]) {
      CLOSERS[name].lastIndex = i;
      const close = CLOSERS[name].exec(html);
      if (!close) return;
      i = close.index;
    }
  }
}

export function attrsOf(inner) {
  const out = Object.create(null);
  for (const m of inner.matchAll(/([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]*)))?/g)) {
    const key = m[1].toLowerCase();
    if (!(key in out)) out[key] = (m[2] ?? m[3] ?? m[4] ?? '').trim();
  }
  return out;
}

const WANTED = new Set(['meta', 'script', 'link', 'img', 'iframe', 'source', 'video', 'audio', 'embed', 'form', 'input', 'html']);
const isHttp = (u = '') => /^http:\/\//i.test(u);

/* Everything the checks need from a page, in one pass. */
export function parsePage(html = '') {
  const page = { generators: [], metaCsp: '', active: new Set(), passive: new Set(), forms: [], hasPassword: false, scripts: [], frames: [], styles: [], webflow: false };
  for (const { name, inner } of eachTag(html)) {
    if (!WANTED.has(name)) continue;
    const a = attrsOf(inner);
    if (name === 'meta') {
      if ((a.name || '').toLowerCase() === 'generator' && a.content) page.generators.push(a.content);
      if ((a['http-equiv'] || '').toLowerCase() === 'content-security-policy') page.metaCsp ||= a.content || '';
    } else if (name === 'form') {
      page.forms.push({ action: a.action || '' });
    } else if (name === 'input') {
      if ((a.type || '').toLowerCase() === 'password') page.hasPassword = true;
    } else if (name === 'html') {
      if ('data-wf-site' in a) page.webflow = true;
    } else if (name === 'link') {
      if (!/\bstylesheet\b/i.test(a.rel || '')) continue;
      if (a.href) page.styles.push(a.href);
      if (isHttp(a.href)) page.active.add(a.href);
    } else {
      const url = a.src || (name === 'embed' ? a.data : '') || '';
      if (name === 'script' && url) page.scripts.push(url);
      if (name === 'iframe' && url) page.frames.push(url);
      if (isHttp(url)) (name === 'script' || name === 'iframe' || name === 'embed' ? page.active : page.passive).add(url);
    }
  }
  // a page can have several generator tags: plugins add their own, often before WordPress's
  return { ...page, generator: page.generators.join(' | '), active: [...page.active], passive: [...page.passive] };
}

/* <script>, <iframe>, stylesheets and plugins loaded over http get blocked ("active");
   images and media get upgraded or warned about ("passive"). */
export function insecureFiles(html = '') {
  const { active, passive } = parsePage(html);
  return { active, passive };
}

/* ---------------- who built it ---------------- */

export const BUILDERS = {
  wordpress: 'WordPress', wix: 'Wix', squarespace: 'Squarespace', webflow: 'Webflow', shopify: 'Shopify', joomla: 'Joomla', drupal: 'Drupal',
  godaddy: 'GoDaddy Website Builder', framer: 'Framer', weebly: 'Weebly', duda: 'Duda',
};
const BY_GENERATOR = [[/wordpress/i, 'wordpress'], [/wix\.com/i, 'wix'], [/squarespace/i, 'squarespace'], [/webflow/i, 'webflow'], [/shopify/i, 'shopify'],
  [/joomla/i, 'joomla'], [/drupal/i, 'drupal'], [/go ?daddy|starfield/i, 'godaddy'], [/framer/i, 'framer'], [/weebly/i, 'weebly'], [/duda/i, 'duda']];
const BY_ASSET = [[/\/wp-(?:content|includes)\//i, 'wordpress'], [/\/\/cdn\.shopify\.com\//i, 'shopify'], [/\/\/(?:static\.wixstatic\.com|static\.parastorage\.com)\//i, 'wix'],
  [/\/\/(?:static1|assets)\.squarespace\.com\//i, 'squarespace'], [/\/\/(?:assets|cdn\.prod)\.website-files\.com\//i, 'webflow'], [/\/\/[\w.-]*framerusercontent\.com\//i, 'framer'],
  [/\/\/cdn\d*\.editmysite\.com\//i, 'weebly'], [/\/\/img\d*\.wsimg\.com\//i, 'godaddy'], [/\/\/irp\.cdn-website\.com\//i, 'duda']];

export function detectBuilder(page) {
  for (const [re, id] of BY_GENERATOR) if (re.test(page.generator)) return id;
  if (page.webflow) return 'webflow';
  for (const url of [...page.scripts, ...page.styles]) for (const [re, id] of BY_ASSET) if (re.test(url)) return id;
  return null;
}

/* The WordPress version a page gives away: its generator tag, or the core block stylesheet's ?ver=. */
export function wordpressVersion(page) {
  const fromTag = /wordpress\s+(\d+(?:\.\d+){1,2})/i.exec(page.generator)?.[1];
  if (fromTag) return fromTag;
  for (const url of page.styles) {
    if (/\/wp-includes\/css\/dist\/block-library\/style(?:\.min)?\.css/i.test(url)) {
      const v = /[?&]ver=(\d+(?:\.\d+){1,2})(?:&|$)/.exec(url)?.[1];
      if (v) return v;
    }
  }
  return null;
}

/* ---------------- old code libraries ---------------- */

const version = (s) => s.split('.').map(Number);
const older = (a, b) => { for (let i = 0; i < 3; i++) { const d = (a[i] ?? 0) - (b[i] ?? 0); if (d) return d < 0; } return false; };

/* Each entry names a published hole and the release that fixed it, so every warning can be looked up. */
const LIBRARIES = [
  { name: 'jQuery', file: /^jquery(?:[-.]\d+(?:\.\d+)*)?(?:[-.]slim)?(?:[-.]min)?\.js$/, dir: /^jquery$/,
    risky: (v) => older(v, [3, 5, 0]), fix: '3.5.0', why: 'cross-site scripting holes, CVE-2020-11022 and CVE-2020-11023' },
  { name: 'jQuery UI', file: /^jquery-ui(?:[-.]\d+(?:\.\d+)*)?(?:[-.]custom)?(?:[-.]min)?\.js$/, dir: /^(?:jqueryui|jquery-ui|ui)$/,
    risky: (v) => older(v, [1, 13, 2]), fix: '1.13.2', why: 'cross-site scripting holes, including CVE-2022-31160' },
  { name: 'Bootstrap', file: /^bootstrap(?:[-.]\d+(?:\.\d+)*)?(?:[-.]bundle)?(?:[-.]min)?\.js$/, dir: /^(?:bootstrap|twitter-bootstrap)$/,
    risky: (v) => older(v, [3, 4, 1]) || (v[0] === 4 && older(v, [4, 3, 1])), fix: '3.4.1 or 4.3.1', why: 'a cross-site scripting hole, CVE-2019-8331' },
  { name: 'AngularJS', file: /^angular(?:[-.]\d+(?:\.\d+)*)?(?:[-.]min)?\.js$/, dir: /^(?:angular|angularjs|angular\.js)$/,
    risky: (v) => v[0] === 1, fix: 'a framework that still gets updates', why: 'security fixes stopped at the end of 2021' },
  { name: 'Lodash', file: /^lodash(?:[-.]\d+(?:\.\d+)*)?(?:[-.]core)?(?:[-.]min)?\.js$/, dir: /^(?:lodash|lodash\.js)$/,
    risky: (v) => older(v, [4, 17, 21]), fix: '4.17.21', why: 'a code injection hole, CVE-2021-23337' },
];

function versionIn(lib, url) {
  let u;
  try { u = new URL(url, 'https://local.invalid/'); } catch { return null; }
  const parts = u.pathname.toLowerCase().split('/').filter(Boolean);
  const file = parts.at(-1) ?? '';
  if (!lib.file.test(file)) return null;
  const inName = /[-.](\d+\.\d+(?:\.\d+)?)/.exec(file)?.[1];
  if (inName) return inName;
  // /ajax/libs/jquery/3.6.0/jquery.min.js and /npm/jquery@3.6.0/dist/jquery.min.js
  for (let k = 0; k < parts.length - 1; k++) {
    const m = /^(?:([a-z][\w.-]*)@)?v?(\d+\.\d+(?:\.\d+)?)$/.exec(parts[k]);
    if (m && lib.dir.test(m[1] ?? parts[k - 1] ?? '')) return m[2];
  }
  // ?ver= only means the library's version on WordPress's own copies; on a theme's copy it's the theme's
  if (parts.includes('wp-includes')) return /[?&]ver=(\d+\.\d+(?:\.\d+)?)(?:&|$)/.exec(u.search)?.[1] ?? null;
  return null;
}

/* Every library whose version shows in a script address, with `risky` set on the ones to update. */
export function libraries(scripts = []) {
  const found = new Map();
  for (const url of scripts) {
    for (const lib of LIBRARIES) {
      const v = versionIn(lib, url);
      if (v) found.set(`${lib.name} ${v}`, { name: lib.name, version: v, risky: lib.risky(version(v)), fix: lib.fix, why: lib.why });
    }
  }
  return [...found.values()];
}

/* ---------------- other companies on the page ---------------- */

const COMPANIES = [
  [/(^|\.)googletagmanager\.com$/, 'Google Tag Manager'], [/(^|\.)google-analytics\.com$/, 'Google Analytics'],
  [/(^|\.)(googleadservices|googlesyndication|doubleclick)\.(com|net)$/, 'Google Ads'], [/(^|\.)(recaptcha\.net|gstatic\.com|googleapis\.com|google\.com)$/, 'Google'],
  [/(^|\.)(facebook\.net|facebook\.com)$/, 'Meta (Facebook)'], [/(^|\.)instagram\.com$/, 'Instagram'], [/(^|\.)(tiktok\.com|ttwstatic\.com)$/, 'TikTok'],
  [/(^|\.)hotjar\.com$/, 'Hotjar'], [/(^|\.)clarity\.ms$/, 'Microsoft Clarity'], [/(^|\.)bing\.com$/, 'Microsoft Bing'], [/(^|\.)(linkedin\.com|licdn\.com)$/, 'LinkedIn'],
  [/(^|\.)(cloudflare\.com|cloudflareinsights\.com)$/, 'Cloudflare'], [/(^|\.)jsdelivr\.net$/, 'jsDelivr'], [/(^|\.)unpkg\.com$/, 'unpkg'], [/(^|\.)jquery\.com$/, 'jQuery'],
  [/(^|\.)stripe\.com$/, 'Stripe'], [/(^|\.)paypal\.com$/, 'PayPal'], [/(^|\.)square(up)?\.com$/, 'Square'], [/(^|\.)(squarespace\.com|squarespace-cdn\.com)$/, 'Squarespace'],
  [/(^|\.)(wixstatic\.com|parastorage\.com|wix\.com)$/, 'Wix'], [/(^|\.)(shopify\.com|shopifycdn\.com|shopifysvc\.com)$/, 'Shopify'], [/(^|\.)klaviyo\.com$/, 'Klaviyo'],
  [/(^|\.)(hubspot\.com|hs-scripts\.com|hs-analytics\.net|hsforms\.net|hscollectedforms\.net)$/, 'HubSpot'], [/(^|\.)(mailchimp\.com|chimpstatic\.com|list-manage\.com)$/, 'Mailchimp'],
  [/(^|\.)(intercom\.io|intercomcdn\.com)$/, 'Intercom'], [/(^|\.)(zdassets\.com|zendesk\.com)$/, 'Zendesk'], [/(^|\.)tawk\.to$/, 'Tawk.to'],
  [/(^|\.)(youtube\.com|youtube-nocookie\.com)$/, 'YouTube'], [/(^|\.)vimeo\.com$/, 'Vimeo'], [/(^|\.)calendly\.com$/, 'Calendly'],
  [/(^|\.)(cookiebot\.com|cookielaw\.org|onetrust\.com)$/, 'a cookie banner service'], [/(^|\.)typekit\.net$/, 'Adobe Fonts'], [/(^|\.)fontawesome\.com$/, 'Font Awesome'],
];

const hostOf = (url) => {
  try { return /^(?:https?:)?\/\//i.test(url) ? new URL(url, 'https://local.invalid/').hostname.toLowerCase() : null; } catch { return null; }
};

/* Names of the outside companies whose scripts or frames the page's HTML loads. */
export function thirdParties(page, siteDomain) {
  const mine = registrable(siteDomain);
  const names = new Set();
  for (const url of [...page.scripts, ...page.frames]) {
    const host = hostOf(url);
    if (!host || registrable(host) === mine) continue;
    names.add(COMPANIES.find(([re]) => re.test(host))?.[1] ?? registrable(host));
  }
  return [...names];
}
