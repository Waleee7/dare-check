/* What kind of name is this? Shared platform addresses, and the "real" domain behind a subdomain. */

// free shared addresses: the platform owns the domain, so its email and registration aren't the site owner's to fix
const SHARED = ['vercel.app', 'netlify.app', 'github.io', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'onrender.com',
  'fly.dev', 'wixsite.com', 'squarespace.com', 'myshopify.com', 'webflow.io', 'framer.website', 'framer.app', 'carrd.co', 'godaddysites.com',
  'wordpress.com', 'blogspot.com', 'glitch.me', 'replit.app', 'surge.sh', 'azurewebsites.net', 'amplifyapp.com', 'up.railway.app', 'lovable.app'];

export const sharedSuffix = (domain) => SHARED.find((s) => domain === s || domain.endsWith('.' + s)) ?? null;

// second levels that are sold like top levels in country domains: example.co.uk, example.com.au
const SECOND_LEVEL = new Set(['com', 'co', 'net', 'org', 'ac', 'edu', 'gov', 'gob', 'gouv', 'mil', 'ltd', 'plc', 'or', 'ne', 'go', 'nom', 'sch']);

/* shop.example.co.uk -> example.co.uk. A small rule instead of the 300 KB public suffix list: when it
   guesses wrong the lookup finds nothing, and the check reports that it couldn't run. */
export function registrable(host) {
  const labels = String(host).toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const [second, top] = labels.slice(-2);
  return labels.slice(top.length === 2 && SECOND_LEVEL.has(second) ? -3 : -2).join('.');
}

/* The other spelling people type, or null when there isn't one (subdomains, shared addresses). */
export function wwwVariant(host) {
  const bare = host.replace(/^www\./, '');
  if (sharedSuffix(bare) || registrable(bare) !== bare) return null;
  return host === bare ? `www.${bare}` : bare;
}
