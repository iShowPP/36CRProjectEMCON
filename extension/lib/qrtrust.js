// Person-to-person trust over QR codes: no server in the middle.
//
//  Contact QR      "this is my EMCON key" (self-signed, so the key really is theirs)
//  Attestation QR  "I vouch for / warn about this domain", signed, bound to the domain,
//                  with an expiry and a nonce
//
// Payloads are compact JSON in base64url behind an "EMCON1:" prefix: an attestation is
// about 330 characters, well inside what a QR code at error-correction level M scans
// reliably from a phone or webcam. Changing any character breaks the signature.
import { te, td, toB64u, fromB64u, toHex, randomBytes, ed25519Sign, ed25519Verify, pubFromDidKey } from './util.js';
import { normDomain } from './domains.js';

export const PREFIX = 'EMCON1:';
export const ATTESTATION_DAYS = 90;

const message = (p) => te.encode(['EMCON-QR-v1', p.t, p.i, p.d || '', p.c || '', p.n || '', p.iat, p.exp || ''].join('|'));

export const encodeQr = (payload) => PREFIX + toB64u(te.encode(JSON.stringify(payload)));

export function decodeQr(text) {
  const s = String(text || '').trim();
  if (!s.startsWith(PREFIX)) throw new Error("That isn't an EMCON QR code.");
  let p;
  try { p = JSON.parse(td.decode(fromB64u(s.slice(PREFIX.length)))); } catch { throw new Error('The QR code is damaged or incomplete.'); }
  if (p?.v !== 1 || !['c', 'a'].includes(p.t)) throw new Error('Unknown EMCON QR version.');
  return p;
}

export async function makeContact({ did, privateKey }, nickname) {
  const p = { v: 1, t: 'c', i: did, n: String(nickname || '').trim().slice(0, 40), iat: Math.floor(Date.now() / 1000) };
  return { ...p, s: toB64u(await ed25519Sign(privateKey, message(p))) };
}

export async function makeAttestation({ did, privateKey }, domain, claim, days = ATTESTATION_DAYS) {
  const d = normDomain(domain);
  if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$|^localhost$/.test(d)) throw new Error('That is not a website address.');
  if (!['safe', 'scam'].includes(claim)) throw new Error('Choose "safe" or "scam".');
  const iat = Math.floor(Date.now() / 1000);
  const p = { v: 1, t: 'a', i: did, d, c: claim === 'safe' ? 's' : 'x', n: toHex(randomBytes(6)), iat, exp: iat + days * 86400 };
  return { ...p, s: toB64u(await ed25519Sign(privateKey, message(p))) };
}

/** Checks signature, shape and expiry. Returns a readable object, or throws with a plain reason. */
export async function verifyQr(p, now = Date.now()) {
  let pub;
  try { pub = pubFromDidKey(p.i); } catch { throw new Error('The QR code has no valid EMCON key.'); }
  if (!p.s || !(await ed25519Verify(pub, fromB64u(p.s), message(p)))) throw new Error('Signature check failed: this QR code was changed or forged.');
  if (p.t === 'a') {
    if (!p.d || !['s', 'x'].includes(p.c) || !p.n || !p.exp) throw new Error('The attestation is incomplete.');
    if (p.exp * 1000 < now) throw new Error('This attestation has expired.');
    if (p.iat * 1000 > now + 5 * 60e3) throw new Error('This attestation is dated in the future.');
    return { kind: 'attestation', issuer: p.i, domain: p.d, claim: p.c === 's' ? 'safe' : 'scam', issued: p.iat * 1000, expires: p.exp * 1000, nonce: p.n, raw: p };
  }
  return { kind: 'contact', did: p.i, nickname: p.n || '', issued: p.iat * 1000, raw: p };
}
