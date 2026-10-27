/* Local dev server: serves public/ with the same headers vercel.json sends in production (minus
   HSTS, which only makes sense over https) and routes /api/scan to the real handler.
   node server.js  ->  http://127.0.0.1:5190 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import handler from './api/scan.js';

const ROOT = path.dirname(new URL(import.meta.url).pathname);
const PUB = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT) || 5190;
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8' };

const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
const pageHeaders = (config.headers.find((h) => h.source === '/(.*)')?.headers ?? []).filter((h) => h.key.toLowerCase() !== 'strict-transport-security');

http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, 'http://local');
  if (pathname === '/api/scan') return handler(req, res);
  for (const { key, value } of pageHeaders) res.setHeader(key, value);
  const file = path.join(PUB, pathname === '/' ? 'index.html' : decodeURIComponent(pathname));
  if (!file.startsWith(PUB + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.statusCode = 404; return res.end('Not found'); }
  res.setHeader('content-type', TYPES[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
}).listen(PORT, '127.0.0.1', () => console.log(`DARE CHECK on http://127.0.0.1:${PORT}`));
