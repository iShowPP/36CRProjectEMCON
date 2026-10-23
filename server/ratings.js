// Crowdsourced website ratings, hard to fake:
//  * every rating is signed by the rater's EMCON key (did:key) and can't be edited by anyone else
//  * a rater counts as a "verified person" only after spending one blind humanity token
//    (one per person per month from the issuer), so a bot farm can't mint 10,000 raters
//  * one rating per person per site: rating again replaces the old one
//  * lookups use a 5-character hash prefix, so the server doesn't learn which site you opened
import crypto from 'node:crypto';
import { db, save, HttpError } from './store.js';
import { spendToken } from './rp.js';
import { fromB64u, ed25519Verify, pubFromDidKey } from '../extension/lib/util.js';
import { normDomain } from '../extension/lib/domains.js';

export const TAGS = ['delivered as promised', 'good support', 'refund given', 'fake store', 'never delivered', 'asked for OTP or PIN', 'impersonates a brand', 'pushy or threatening'];
const prefixOf = (domain) => crypto.createHash('sha256').update(domain).digest('hex').slice(0, 5);
const hits = new Map();
function limit(key, max, ms) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < ms);
  if (recent.length >= max) throw new HttpError(429, 'Too many ratings from here. Try again later.');
  recent.push(now); hits.set(key, recent);
}
async function checkSig(did, sig, msg) {
  let pub;
  try { pub = pubFromDidKey(did); } catch { throw new HttpError(400, 'invalid key'); }
  if (!sig || !(await ed25519Verify(pub, fromB64u(sig), msg))) throw new HttpError(401, 'signature invalid');
}

export default async function ratings(route) {
  db.ratings ||= { byDomain: {}, humans: {}, spent: {} };
  const R = db.ratings;

  route('GET', '/api/ratings/tags', () => TAGS);

  // Prove "a real, verified person holds this key" once, by spending a humanity token.
  route('POST', '/api/ratings/verify', async ({ body, ip }) => {
    limit('verify:' + ip, 20, 60 * 60e3);
    const { did, token, sig } = body;
    await checkSig(did, sig, `EMCON-RATER-v1|${did}|${token?.t || ''}`);
    if (R.humans[did]) return { verified: true };
    await spendToken(token, R.spent);
    R.humans[did] = { at: Date.now() };
    save();
    return { verified: true };
  });

  route('POST', '/api/ratings', async ({ body, ip }) => {
    limit('rate:' + ip, 60, 60 * 60e3);
    const domain = normDomain(body.domain);
    const stars = Math.round(Number(body.stars));
    const sent = (Array.isArray(body.tags) ? body.tags : []).map((t) => String(t).slice(0, 60)).slice(0, 8);
    const tags = sent.filter((t) => TAGS.includes(t)).slice(0, 4);
    const iat = Number(body.iat);
    if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$|^localhost$/.test(domain)) throw new HttpError(400, 'not a website');
    if (!(stars >= 1 && stars <= 5)) throw new HttpError(400, 'stars must be 1 to 5');
    if (!(Math.abs(Date.now() - iat) < 10 * 60e3)) throw new HttpError(400, 'stale rating');
    // the signature covers exactly what the rater sent; unknown tags are dropped afterwards
    await checkSig(body.did, body.sig, `EMCON-RATE-v1|${body.did}|${domain}|${stars}|${sent.join(',')}|${iat}`);
    (R.byDomain[domain] ||= {})[body.did] = { stars, tags, at: iat, sig: body.sig };
    save();
    return { ok: true, verifiedRater: !!R.humans[body.did] };
  });

  route('GET', '/api/ratings', ({ query }) => {
    const prefix = String(query.prefix || '').toLowerCase();
    if (!/^[0-9a-f]{5}$/.test(prefix)) throw new HttpError(400, 'send a 5-character hash prefix');
    const out = [];
    for (const [domain, byDid] of Object.entries(R.byDomain)) {
      if (prefixOf(domain) !== prefix) continue;
      for (const [did, r] of Object.entries(byDid)) out.push({ domain, did, stars: r.stars, tags: r.tags, at: r.at, human: !!R.humans[did] });
    }
    return { ratings: out };
  });
}
