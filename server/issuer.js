// Ghost Engine issuer: verifies a person ONCE, then hands out unlinkable blind tokens.
//
// Loophole fixed: a self-generated "I am over 18" proof proves nothing. Someone has
// to attest it once. The issuer does that, but thanks to blind signatures it can
// never learn where the resulting tokens are spent.

import crypto from 'node:crypto';
import { db, save, HttpError } from './store.js';
import { rsaJwk } from './keys.js';
import { signBlinded } from '../extension/lib/blindrsa.js';
import { fromB64u, toHex, sha256, bytesToBigInt } from '../extension/lib/util.js';

// One RSA key per claim bundle, so a token proves exactly its bundle and nothing more.
const BUNDLES = { human: ['human'], 'human+18': ['human', 'over18'] };
const QUOTA_PER_30_DAYS = 20; // anti-Sybil: bounds how many accounts one human can mint per month
const MAX_PER_REQUEST = 10;

export const issuerKeys = {};

export default async function issuer(route) {
  db.issuer ||= { keys: {}, enrollments: {} };
  for (const [bundle, claims] of Object.entries(BUNDLES)) {
    if (!db.issuer.keys[bundle]) {
      db.issuer.keys[bundle] = rsaJwk('issuer/' + bundle);
      save();
    }
    const j = db.issuer.keys[bundle];
    const big = (k) => bytesToBigInt(fromB64u(j[k]));
    const n = big('n');
    issuerKeys[bundle] = {
      bundle, claims, n, e: big('e'),
      keyId: toHex(await sha256(fromB64u(j.n))).slice(0, 16),
      priv: { n, p: big('p'), q: big('q'), dp: big('dp'), dq: big('dq'), qi: big('qi') },
    };
  }

  // Published at one fixed URL for everyone. Clients pin these, which defeats the
  // "issuer uses a unique key per user to tag them" attack (key consistency).
  route('GET', '/api/issuer/keys', () =>
    Object.fromEntries(Object.values(issuerKeys).map((k) => [k.bundle, { keyId: k.keyId, n: k.n.toString(16), e: k.e.toString(16), claims: k.claims }])));

  // DEMO stand-in for a one-time KYC / liveness check (ID scan, bank KYC, eID...).
  // Only the eligibility result is kept; the date of birth is discarded.
  route('POST', '/api/issuer/enroll', ({ body }) => {
    const dob = new Date(body.dob);
    if (!body.dob || isNaN(dob)) throw new HttpError(400, 'date of birth required');
    const age = (Date.now() - dob.getTime()) / (365.2425 * 864e5);
    if (age < 13 || age > 130) throw new HttpError(400, 'age outside supported range');
    const id = crypto.randomBytes(16).toString('hex');
    const bundles = ['human', ...(age >= 18 ? ['human+18'] : [])];
    db.issuer.enrollments[id] = { bundles, issued: [], created: Date.now() };
    save();
    return { enrollmentId: id, bundles };
  });

  route('POST', '/api/issuer/issue', ({ body }) => {
    const e = db.issuer.enrollments[body.enrollmentId];
    if (!e) throw new HttpError(403, 'unknown enrollment');
    const key = issuerKeys[body.bundle];
    if (!key || !e.bundles.includes(body.bundle)) throw new HttpError(403, 'not eligible for this claim bundle');
    if (body.keyId !== key.keyId) throw new HttpError(409, 'client pinned a different issuer key');
    const blinded = (body.blinded || []).slice(0, MAX_PER_REQUEST).map((h) => BigInt('0x' + h));
    const since = Date.now() - 30 * 864e5;
    e.issued = e.issued.filter((x) => x.at > since);
    const used = e.issued.filter((x) => x.bundle === body.bundle).reduce((a, x) => a + x.n, 0);
    if (used + blinded.length > QUOTA_PER_30_DAYS) throw new HttpError(429, `monthly token quota reached (${QUOTA_PER_30_DAYS} per claim bundle)`);
    let signatures;
    try { signatures = blinded.map((b) => signBlinded(b, key.priv).toString(16)); } catch (err) { throw new HttpError(400, err.message); }
    e.issued.push({ at: Date.now(), bundle: body.bundle, n: blinded.length });
    save();
    return { signatures, remaining: QUOTA_PER_30_DAYS - used - blinded.length };
  });
}
