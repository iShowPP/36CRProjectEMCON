// "ShopNorth" — a demo relying party that accepts EMCON Ghost sign-in.
// It learns a per-site pseudonym and the claims proven by a blind token. Nothing else.

import crypto from 'node:crypto';
import { db, save, HttpError } from './store.js';
import { issuerKeys } from './issuer.js';
import { verify } from '../extension/lib/blindrsa.js';
import { fromB64u, fromHex, ed25519Verify } from '../extension/lib/util.js';

const CHALLENGE_TTL = 5 * 60e3;

/** Checks a Ghost presentation's signature over this origin + challenge. Throws on failure. */
export async function checkPresentation(origin, challenge, p) {
  if (!p?.pseudonym || !p.sig) throw new HttpError(400, 'missing presentation');
  // The signature covers OUR origin: a phishing site relaying this sign-in to us fails here.
  const pub = fromB64u(p.pseudonym);
  const msg = `EMCON-GHOST-v1|${origin}|${challenge}|${p.token ? p.token.t : ''}`;
  if (pub.length !== 32 || !(await ed25519Verify(pub, fromB64u(p.sig), msg))) {
    throw new HttpError(401, 'signature invalid (wrong origin, replay, or tampering)');
  }
}

/** Verifies and spends a blind humanity token; returns the claims it proves. */
export async function spendToken(token, spent) {
  if (!token) throw new HttpError(428, 'new accounts need an EMCON humanity token', { needToken: true });
  const key = Object.values(issuerKeys).find((k) => k.keyId === token.keyId);
  if (!key) throw new HttpError(401, 'token from unknown issuer key');
  if (!(await verify(fromHex(token.t), BigInt('0x' + token.s), key))) throw new HttpError(401, 'token signature invalid');
  if (spent[token.t]) throw new HttpError(409, 'token already spent (Sybil / replay blocked)');
  spent[token.t] = Date.now();
  return key.claims;
}

export default async function rp(route) {
  db.rp ||= { challenges: {}, sites: {} };

  route('GET', '/api/rp/challenge', ({ origin }) => {
    const now = Date.now();
    for (const [c, t] of Object.entries(db.rp.challenges)) if (now - t > CHALLENGE_TTL) delete db.rp.challenges[c];
    const challenge = crypto.randomBytes(16).toString('hex');
    db.rp.challenges[challenge] = now;
    return { challenge, origin };
  });

  route('POST', '/api/rp/auth', async ({ body, origin }) => {
    const { challenge, presentation: p } = body;
    const issued = db.rp.challenges[challenge];
    delete db.rp.challenges[challenge]; // single use: blocks replay
    if (!issued || Date.now() - issued > CHALLENGE_TTL) throw new HttpError(400, 'challenge expired or already used');
    await checkPresentation(origin, challenge, p);

    // Each origin keeps its own accounts, so localhost and 127.0.0.1 behave like two unrelated companies.
    const site = (db.rp.sites[origin] ||= { accounts: {}, spent: {} });
    let acct = site.accounts[p.pseudonym];
    const isNew = !acct;
    if (isNew) {
      const claims = await spendToken(p.token, site.spent);
      acct = site.accounts[p.pseudonym] = { handle: 'ghost_' + p.pseudonym.replace(/[^a-z0-9]/gi, '').slice(0, 8).toLowerCase(), created: Date.now(), claims, logins: 0 };
    }
    acct.logins++;
    acct.lastLogin = Date.now();
    save();
    return {
      newAccount: isNew,
      account: acct,
      whatThisSiteKnows: { pseudonym: p.pseudonym, claims: acct.claims, email: null, name: null, phone: null, crossSiteId: null },
    };
  });

  route('GET', '/api/rp/accounts', ({ origin }) => ({ origin, accounts: Object.values(db.rp.sites[origin]?.accounts || {}) }));
}
