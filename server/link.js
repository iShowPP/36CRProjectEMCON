// "Check a link": follows a link's redirects (HTTP 3xx and <meta refresh>) without the
// user's browser ever opening it, so a short link from an SMS can be judged by where it
// really lands. Only the link the user pasted is sent here; nothing is stored.
//
// Safety: refuses private-network targets when hosted (no SSRF into the host's network),
// times out, reads at most 64 KB of a page, and rate-limits per client.

import dns from 'node:dns/promises';
import net from 'node:net';
import { HttpError } from './store.js';
import { HOSTED } from './config.js';

const MAX_HOPS = 10;
const TIMEOUT_MS = 6000;
const PER_MINUTE = 30;
const hits = new Map(); // client -> recent timestamps

export function privateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return privateIp(v.slice(7));
  return v === '::' || v === '::1' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}

export async function assertPublic(host) {
  if (!HOSTED) return; // local development: the demo links point at localhost
  const h = host.replace(/^\[|\]$/g, '');
  const addrs = net.isIP(h) ? [h] : (await dns.lookup(h, { all: true }).catch(() => [])).map((a) => a.address);
  if (!addrs.length) throw new HttpError(400, `${host} does not resolve`);
  if (addrs.some(privateIp)) throw new HttpError(400, 'that link points into a private network');
}

// Pages that redirect with <meta http-equiv="refresh"> (common on phishing kits and some shorteners).
async function metaRefresh(res) {
  if (!res.body || !/text\/html/i.test(res.headers.get('content-type') || '')) { res.body?.cancel().catch(() => {}); return null; }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let html = '';
  while (html.length < 65536) {
    const { done, value } = await reader.read();
    if (done) break;
    html += dec.decode(value, { stream: true });
  }
  reader.cancel().catch(() => {});
  const m = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']?\s*\d+\s*;\s*url\s*=\s*['"]?([^"'>\s]+)/i.exec(html);
  // the URL sits in an HTML attribute: decode its entities (wa.me writes &amp;, which otherwise loops)
  return m ? m[1].replace(/&(amp|#38|#x26);/gi, '&').replace(/&(quot|#34);/gi, '"').replace(/&#39;/g, "'") : null;
}

export default async function link(route) {
  route('GET', '/api/link/expand', async ({ query, headers }) => {
    const client = String(headers['x-forwarded-for'] || '').split(',')[0].trim() || 'local';
    const now = Date.now();
    const recent = (hits.get(client) || []).filter((t) => now - t < 60e3);
    if (recent.length >= PER_MINUTE) throw new HttpError(429, 'too many link checks; try again in a minute');
    hits.set(client, [...recent, now]);

    return expandLink(query.url);
  });
}

/** Follow a link's redirects without a browser: { hops, final, complete }. */
export async function expandLink(raw) {
  let u;
  try { u = new URL(String(raw || '')); } catch { throw new HttpError(400, 'not a valid link'); }
  if (!/^https?:$/.test(u.protocol)) throw new HttpError(400, 'only http and https links can be checked');

  const hops = [];
  for (let i = 0; i < MAX_HOPS; i++) {
    await assertPublic(u.hostname);
    let res;
    try {
      res = await fetch(u, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS), headers: { 'user-agent': 'Mozilla/5.0 (EMCON link check)', accept: 'text/html,*/*' } });
    } catch {
      hops.push({ url: u.href, error: 'unreachable' });
      return { hops, final: u.href, complete: false };
    }
    const loc = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && loc) {
      res.body?.cancel().catch(() => {});
      hops.push({ url: u.href, status: res.status, leaves: 'redirect' });
      u = new URL(loc, u);
      if (!/^https?:$/.test(u.protocol)) break;
      continue;
    }
    const refresh = res.ok ? await metaRefresh(res) : (res.body?.cancel().catch(() => {}), null);
    if (refresh) {
      hops.push({ url: u.href, status: res.status, leaves: 'page redirect' });
      u = new URL(refresh, u);
      continue;
    }
    hops.push({ url: u.href, status: res.status });
    return { hops, final: u.href, complete: true };
  }
  return { hops, final: u.href, complete: false };
}
