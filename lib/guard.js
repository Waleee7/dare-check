/* SSRF guard. DARE CHECK fetches an address a stranger typed in, so every request has to stay on
   the public internet. A target is checked twice: the name when it's typed, and every resolved
   address at connect time, which also covers redirects and DNS rebinding. */
import dns from 'node:dns';
import net from 'node:net';

const V4 = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const V6 = [
  ['::', 128], ['::1', 128], ['64:ff9b:1::', 48], ['100::', 64], ['2001::', 23], ['2001:db8::', 32],
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
];
const blocked = new net.BlockList();
for (const [a, p] of V4) blocked.addSubnet(a, p, 'ipv4');
for (const [a, p] of V6) blocked.addSubnet(a, p, 'ipv6');

// names that only mean something on a private network (or are reserved for docs and tests)
const PRIVATE_NAME = /\.(local|localhost|internal|intranet|lan|home|corp|home\.arpa|test|invalid|example)$/;

export function fail(message, code = 'EINPUT') {
  return Object.assign(new Error(message), { code, expose: true });
}

// the eight 16-bit groups of an IPv6 address, including forms with a trailing dotted quad
function groups6(ip) {
  let s = ip.toLowerCase().split('%')[0];
  const quad = s.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (quad) {
    const [a, b, c, d] = quad.slice(1).map(Number);
    s = s.slice(0, -quad[0].length) + ((a << 8) | b).toString(16) + ':' + ((c << 8) | d).toString(16);
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail === undefined ? null : tail ? tail.split(':') : [];
  const all = t === null ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return all.map((x) => parseInt(x || '0', 16));
}
const quadOf = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');

export function isPublicIP(ip) {
  const family = net.isIP(ip);
  if (family === 4) return !blocked.check(ip, 'ipv4');
  if (family !== 6) return false;
  const g = groups6(ip);
  // IPv6 forms that carry an IPv4 address inside: mapped (::ffff:a.b.c.d), the old
  // "compatible" form (::a.b.c.d), NAT64 (64:ff9b::/96) and 6to4 (2002::/16)
  const lead = g.slice(0, 5).every((v) => v === 0);
  if (lead && g[5] === 0xffff) return isPublicIP(quadOf(g[6], g[7]));
  if (lead && g[5] === 0 && g[6] !== 0) return isPublicIP(quadOf(g[6], g[7]));
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((v) => v === 0)) return isPublicIP(quadOf(g[6], g[7]));
  if (g[0] === 0x2002) return isPublicIP(quadOf(g[1], g[2]));
  return !blocked.check(ip, 'ipv6');
}

/* What someone typed -> { host, domain }, or a plain-English error. */
export function normalizeTarget(input) {
  let s = String(input ?? '').trim();
  if (!s) throw fail('Type a website address, like yourbusiness.com.');
  if (s.length > 2048) throw fail('That address is too long.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { throw fail("That doesn't look like a website address."); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw fail('Only http:// and https:// websites can be checked.');
  if (u.username || u.password) throw fail('Leave out usernames and passwords.');
  if (u.port) throw fail('Leave out the port number. DARE CHECK only looks at the normal web ports.');
  const host = u.hostname.toLowerCase().replace(/\.$/, '');
  if (net.isIP(host.replace(/^\[|\]$/g, ''))) throw fail('Type the domain name instead of an IP address.');
  const labels = host.split('.');
  if (labels.length < 2 || host.length > 253 || !/^[a-z0-9.-]+$/.test(host) || !/[a-z]/.test(labels.at(-1)) ||
      labels.some((l) => !l || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) {
    throw fail("That doesn't look like a public website address.");
  }
  if (PRIVATE_NAME.test(host)) throw fail("That address only works on a private network, so it can't be checked from here.");
  return { host, domain: host.replace(/^www\./, '') };
}

/* A dns.lookup replacement for http(s).request: resolves every address and refuses the
   connection if any of them is private. Supports both the single and the `all` callback forms. */
export function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  const opts = typeof options === 'number' ? { family: options } : { ...options };
  dns.lookup(hostname, { ...opts, all: true }, (err, addrs) => {
    if (err) return callback(err);
    if (!addrs.length || addrs.some((a) => !isPublicIP(a.address))) {
      return callback(fail("That address points to a private network, so it can't be checked.", 'EBLOCKED'));
    }
    if (opts.all) callback(null, addrs);
    else callback(null, addrs[0].address, addrs[0].family);
  });
}

/* Redirects can name an IP directly, and Node skips the lookup for IP hosts, so check those here. */
export function assertPublicUrl(u, { allowPorts = false } = {}) {
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw fail('The site redirected somewhere that isn\'t a web page.', 'EREDIRECT');
  if (u.port && !allowPorts) throw fail('The site redirected to an unusual port, so DARE CHECK stopped there.', 'EREDIRECT');
  const h = u.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(h) && !isPublicIP(h)) throw fail("That address points to a private network, so it can't be checked.", 'EBLOCKED');
}
