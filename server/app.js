import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, MEDIA_DIR, HttpError, flush } from './store.js';
import issuer from './issuer.js';
import rp from './rp.js';
import prov from './prov.js';
import vault from './vault.js';
import wot from './wot.js';
import timestamp from './timestamp.js';
import link from './link.js';
import { publicUrls } from './config.js';

// Demo "link shortener" hops for the scam-chain demo: /s/qk50 -> /r?to=/claim.html -> /claim.html.
// Only same-site paths are allowed, so this is not an open redirect.
const SHORT_LINKS = { qk50: '/claim.html' };
const safePath = (p) => (typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !p.includes('\\') ? p : '/');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
};
// URL prefix -> directory. /lib exposes the extension's shared crypto to the demo pages.
const STATIC = [['/lib/', path.join(ROOT, 'extension', 'lib')], ['/media/', MEDIA_DIR], ['/', path.join(ROOT, 'web')]];

export async function createApp() {
  const routes = [];
  const route = (method, pattern, handler) => {
    const keys = [];
    const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    routes.push({ method, re, keys, handler });
  };
  for (const mod of [issuer, rp, prov, vault, wot, timestamp, link]) await mod(route);
  route('GET', '/api/config', ({ origin }) => publicUrls(origin));

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'content-type, x-vault-session');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    if (req.method === 'OPTIONS') return res.writeHead(204).end();

    const short = /^\/s\/(\w+)$/.exec(url.pathname);
    if (short) return res.writeHead(302, { location: '/r?to=' + encodeURIComponent(SHORT_LINKS[short[1]] || '/') }).end();
    if (url.pathname === '/r') return res.writeHead(302, { location: safePath(url.searchParams.get('to')) }).end();

    if (url.pathname.startsWith('/api/')) {
      const send = (status, obj) => res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(obj));
      try {
        const r = routes.find((r) => r.method === req.method && r.re.test(url.pathname));
        if (!r) throw new HttpError(404, 'no such endpoint');
        const m = r.re.exec(url.pathname);
        const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
        const body = req.method === 'POST' ? await readJson(req) : {};
        const origin = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;
        const result = await r.handler({ body, params, query: Object.fromEntries(url.searchParams), headers: req.headers, origin });
        send(200, result ?? { ok: true });
      } catch (e) {
        if (!(e instanceof HttpError)) console.error(e);
        send(e.status || 500, { error: e.message, ...(e.data || {}) });
      }
      return;
    }
    serveStatic(url.pathname, res);
  });
  server.on('close', flush);
  return server;
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 30e6) { reject(new HttpError(413, 'body too large')); req.destroy(); }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!size) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new HttpError(400, 'invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function serveStatic(pathname, res) {
  const [prefix, dir] = STATIC.find(([p]) => pathname.startsWith(p));
  let rel = decodeURIComponent(pathname.slice(prefix.length)) || 'index.html';
  const file = path.resolve(dir, rel);
  if (!file.startsWith(path.resolve(dir))) return res.writeHead(403).end();
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
    res.writeHead(200, { 'content-type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'cache-control': 'no-store' });
    fs.createReadStream(file).pipe(res);
  });
}
